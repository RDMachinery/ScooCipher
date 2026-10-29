import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * TraceCipher - an authenticated stream cipher built around the two-row trace transform.
 *
 * How it works:
 *   1. A secret 256-bit key and a fresh 64-bit nonce seed a ChaCha-style keystream generator,
 *      which produces the "random row" 64 bytes at a time.
 *   2. Each data bit is traced across the random row and its inverse: the path goes to
 *      whichever row holds the data bit in that column. The path (top = 0, bottom = 1)
 *      is the ciphertext. Decryption traces the ciphertext across the same rows.
 *   3. An HMAC-SHA256 tag over the nonce and ciphertext detects any tampering.
 *
 * Differences from ChaCha20: its own constants ("two rows, trace!"), different rotation
 * amounts in the mixing function (13, 7, 17, 11), a per-round constant injected into the
 * state, a 64-bit nonce with a 64-bit block counter, and HMAC-SHA256 instead of Poly1305.
 *
 * EDUCATIONAL ONLY. The keystream generator has not been analysed by cryptographers, so
 * it must not be trusted with real secrets. Use ChaCha20-Poly1305 or AES-GCM for that.
 *
 * Usage (Java 17+):
 *   java TraceCipher.java demo
 *   java TraceCipher.java keygen  <keyfile>
 *   java TraceCipher.java encrypt <keyfile> <input> <output>
 *   java TraceCipher.java decrypt <keyfile> <input> <output>
 *
 * Author: Mario Gianota
 */
public class TraceCipher {

    public static final int KEY_BYTES = 32;
    public static final int NONCE_BYTES = 8;
    public static final int TAG_BYTES = 32;
    private static final int BLOCK_BYTES = 64;
    private static final int DOUBLE_ROUNDS = 10;   // 20 rounds in total
    private static final int[] CONSTANTS =
            littleEndianWords("two rows, trace!".getBytes(StandardCharsets.US_ASCII));
    private static final SecureRandom RNG = new SecureRandom();

    // =====================================================================
    // 1. The two-row trace transform
    // =====================================================================

    /** Traces one column: returns 0 if the data bit is found on the top row, 1 if on the bottom. */
    static int traceBit(int dataBit, int rowBit) {
        int top = rowBit;
        int bottom = 1 - rowBit;          // the inverted row
        if (dataBit == top) return 0;
        if (dataBit == bottom) return 1;
        throw new IllegalArgumentException("bits must be 0 or 1");
    }

    /** Traces eight columns at once, most significant bit first. */
    static int traceByte(int data, int row) {
        int out = 0;
        for (int i = 7; i >= 0; i--) {
            out = (out << 1) | traceBit((data >>> i) & 1, (row >>> i) & 1);
        }
        return out;
    }

    /** Draws the traced path for one byte using - for the top row and _ for the bottom. */
    static String drawPath(int data, int row) {
        StringBuilder sb = new StringBuilder();
        int previous = -1;
        for (int i = 7; i >= 0; i--) {
            int level = traceBit((data >>> i) & 1, (row >>> i) & 1);
            if (previous == 1 && level == 0) sb.append("/ ");
            if (previous == 0 && level == 1) sb.append("\\ ");
            sb.append(level == 0 ? "- " : "_ ");
            previous = level;
        }
        return sb.toString().trim();
    }

    // =====================================================================
    // 2. The keystream generator (produces the random rows)
    // =====================================================================

    private static void mix(int[] x, int a, int b, int c, int d) {
        x[a] += x[b]; x[d] = Integer.rotateLeft(x[d] ^ x[a], 13);
        x[c] += x[d]; x[b] = Integer.rotateLeft(x[b] ^ x[c], 7);
        x[a] += x[b]; x[d] = Integer.rotateLeft(x[d] ^ x[a], 17);
        x[c] += x[d]; x[b] = Integer.rotateLeft(x[b] ^ x[c], 11);
    }

    /** Generates one 64-byte random row from the key, nonce and block number. */
    static byte[] keystreamBlock(byte[] key, byte[] nonce, long counter) {
        int[] state = new int[16];
        System.arraycopy(CONSTANTS, 0, state, 0, 4);
        System.arraycopy(littleEndianWords(key), 0, state, 4, 8);
        state[12] = (int) counter;
        state[13] = (int) (counter >>> 32);
        int[] n = littleEndianWords(nonce);
        state[14] = n[0];
        state[15] = n[1];

        int[] x = state.clone();
        for (int r = 0; r < DOUBLE_ROUNDS; r++) {
            x[0] ^= 0x9E3779B9 * (r + 1);          // per-round constant
            mix(x, 0, 4, 8, 12); mix(x, 1, 5, 9, 13);   // columns
            mix(x, 2, 6, 10, 14); mix(x, 3, 7, 11, 15);
            mix(x, 0, 5, 10, 15); mix(x, 1, 6, 11, 12); // diagonals
            mix(x, 2, 7, 8, 13); mix(x, 3, 4, 9, 14);
        }

        byte[] out = new byte[BLOCK_BYTES];
        for (int i = 0; i < 16; i++) {
            int w = x[i] + state[i];               // feed-forward makes it one-way
            out[4 * i]     = (byte) w;
            out[4 * i + 1] = (byte) (w >>> 8);
            out[4 * i + 2] = (byte) (w >>> 16);
            out[4 * i + 3] = (byte) (w >>> 24);
        }
        return out;
    }

    // =====================================================================
    // 3. Encryption and decryption
    // =====================================================================

    /** Traces every byte of the input across successive random rows. */
    static byte[] traceStream(byte[] key, byte[] nonce, long firstCounter, byte[] in) {
        byte[] out = new byte[in.length];
        long counter = firstCounter;
        for (int off = 0; off < in.length; off += BLOCK_BYTES) {
            byte[] row = keystreamBlock(key, nonce, counter++);
            int n = Math.min(BLOCK_BYTES, in.length - off);
            for (int i = 0; i < n; i++) {
                out[off + i] = (byte) traceByte(in[off + i] & 0xFF, row[i] & 0xFF);
            }
        }
        return out;
    }

    /** Block 0 of the keystream is reserved for the authentication key. */
    private static byte[] tag(byte[] key, byte[] nonce, byte[] ciphertext) throws GeneralSecurityException {
        byte[] macKey = Arrays.copyOf(keystreamBlock(key, nonce, 0), 32);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
        mac.update(nonce);
        return mac.doFinal(ciphertext);
    }

    /** Returns nonce || ciphertext || tag. */
    public static byte[] encrypt(byte[] key, byte[] plaintext) throws GeneralSecurityException {
        checkKey(key);
        byte[] nonce = new byte[NONCE_BYTES];
        RNG.nextBytes(nonce);
        byte[] ciphertext = traceStream(key, nonce, 1, plaintext);
        byte[] t = tag(key, nonce, ciphertext);

        byte[] out = new byte[NONCE_BYTES + ciphertext.length + TAG_BYTES];
        System.arraycopy(nonce, 0, out, 0, NONCE_BYTES);
        System.arraycopy(ciphertext, 0, out, NONCE_BYTES, ciphertext.length);
        System.arraycopy(t, 0, out, NONCE_BYTES + ciphertext.length, TAG_BYTES);
        return out;
    }

    public static byte[] decrypt(byte[] key, byte[] message) throws GeneralSecurityException {
        checkKey(key);
        if (message.length < NONCE_BYTES + TAG_BYTES) {
            throw new GeneralSecurityException("Message is too short to be valid");
        }
        byte[] nonce = Arrays.copyOfRange(message, 0, NONCE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(message, NONCE_BYTES, message.length - TAG_BYTES);
        byte[] t = Arrays.copyOfRange(message, message.length - TAG_BYTES, message.length);
        if (!MessageDigest.isEqual(t, tag(key, nonce, ciphertext))) {
            throw new GeneralSecurityException("Authentication failed: wrong key, or the message has been altered");
        }
        return traceStream(key, nonce, 1, ciphertext);
    }

    // =====================================================================
    // 4. Demonstration and tests
    // =====================================================================

    static void demo() throws GeneralSecurityException {
        HexFormat hex = HexFormat.of();

        System.out.println("=== 1. The trace on the original example ===");
        int row = 0b10110010, data = 0b01101001;
        System.out.println("Random row: " + bits(row));
        System.out.println("Inverted:   " + bits(~row & 0xFF));
        System.out.println("Data:       " + bits(data));
        System.out.println("Path:       " + drawPath(data, row));
        System.out.println("Output:     " + bits(traceByte(data, row)));

        System.out.println("\n=== 2. Trace equals XOR for every pair of bytes ===");
        int mismatches = 0;
        for (int d = 0; d < 256; d++)
            for (int r = 0; r < 256; r++)
                if (traceByte(d, r) != (d ^ r)) mismatches++;
        System.out.println("Mismatches out of 65,536 pairs: " + mismatches);

        System.out.println("\n=== 3. Round trip ===");
        byte[] key = new byte[KEY_BYTES];
        RNG.nextBytes(key);
        String text = "Meet me by the old pier at midnight. Bring the schematics.";
        byte[] message = encrypt(key, text.getBytes(StandardCharsets.UTF_8));
        String back = new String(decrypt(key, message), StandardCharsets.UTF_8);
        System.out.println("Plaintext:  " + text);
        System.out.println("Encrypted:  " + hex.formatHex(message, 0, 32) + "...");
        System.out.println("Decrypted:  " + back);
        System.out.println("Match:      " + text.equals(back));

        System.out.println("\n=== 4. Same message twice gives different ciphertexts (fresh nonce) ===");
        byte[] again = encrypt(key, text.getBytes(StandardCharsets.UTF_8));
        System.out.println("First:      " + hex.formatHex(message, 0, 24) + "...");
        System.out.println("Second:     " + hex.formatHex(again, 0, 24) + "...");

        System.out.println("\n=== 5. Tampering is detected ===");
        byte[] tampered = message.clone();
        tampered[NONCE_BYTES] ^= 1;                // flip one ciphertext bit
        try {
            decrypt(key, tampered);
            System.out.println("Tampered message accepted (this should not happen)");
        } catch (GeneralSecurityException e) {
            System.out.println("Rejected:   " + e.getMessage());
        }
        byte[] wrongKey = key.clone();
        wrongKey[0] ^= 1;
        try {
            decrypt(wrongKey, message);
            System.out.println("Wrong key accepted (this should not happen)");
        } catch (GeneralSecurityException e) {
            System.out.println("Wrong key:  " + e.getMessage());
        }

        System.out.println("\n=== 6. Avalanche: flip one input bit, count changed row bits (ideal 50%) ===");
        avalanche("key bit", true);
        avalanche("nonce bit", false);

        System.out.println("\n=== 7. Bit balance of the random rows (ideal 50% ones) ===");
        long ones = 0, total = 0;
        byte[] nonce = new byte[NONCE_BYTES];
        for (long c = 0; c < 20_000; c++) {
            for (byte b : keystreamBlock(key, nonce, c)) ones += Integer.bitCount(b & 0xFF);
            total += BLOCK_BYTES * 8L;
        }
        System.out.printf("Ones: %.4f%% of %,d bits%n", 100.0 * ones / total, total);
    }

    private static void avalanche(String label, boolean flipKey) {
        int trials = 2000, min = Integer.MAX_VALUE, max = 0;
        long sum = 0;
        for (int t = 0; t < trials; t++) {
            byte[] key = new byte[KEY_BYTES], nonce = new byte[NONCE_BYTES];
            RNG.nextBytes(key);
            RNG.nextBytes(nonce);
            byte[] key2 = key.clone(), nonce2 = nonce.clone();
            if (flipKey) {
                int bit = RNG.nextInt(KEY_BYTES * 8);
                key2[bit / 8] ^= (byte) (1 << (bit % 8));
            } else {
                int bit = RNG.nextInt(NONCE_BYTES * 8);
                nonce2[bit / 8] ^= (byte) (1 << (bit % 8));
            }
            byte[] a = keystreamBlock(key, nonce, 1), b = keystreamBlock(key2, nonce2, 1);
            int diff = 0;
            for (int i = 0; i < BLOCK_BYTES; i++) diff += Integer.bitCount((a[i] ^ b[i]) & 0xFF);
            sum += diff;
            min = Math.min(min, diff);
            max = Math.max(max, diff);
        }
        System.out.printf("Flip one %-9s average %.2f%% changed (min %d, max %d of 512 bits)%n",
                label + ":", 100.0 * sum / (trials * 512.0), min, max);
    }

    // =====================================================================
    // 5. Command line and helpers
    // =====================================================================

    public static void main(String[] args) throws Exception {
        if (args.length == 0) { usage(); return; }
        try {
            switch (args[0]) {
                case "demo" -> demo();
                case "keygen" -> {
                    if (args.length != 2) { usage(); return; }
                    byte[] key = new byte[KEY_BYTES];
                    RNG.nextBytes(key);
                    Files.writeString(Path.of(args[1]), HexFormat.of().formatHex(key) + "\n",
                            StandardOpenOption.CREATE_NEW);
                    System.out.println("New key written to " + args[1] + ". Keep it secret.");
                }
                case "encrypt" -> {
                    if (args.length != 4) { usage(); return; }
                    byte[] key = readKey(args[1]);
                    Files.write(Path.of(args[3]), encrypt(key, Files.readAllBytes(Path.of(args[2]))));
                    System.out.println("Encrypted " + args[2] + " -> " + args[3]);
                }
                case "decrypt" -> {
                    if (args.length != 4) { usage(); return; }
                    byte[] key = readKey(args[1]);
                    Files.write(Path.of(args[3]), decrypt(key, Files.readAllBytes(Path.of(args[2]))));
                    System.out.println("Decrypted " + args[2] + " -> " + args[3]);
                }
                default -> usage();
            }
        } catch (GeneralSecurityException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void usage() {
        System.out.println("""
                TraceCipher - educational stream cipher using the two-row trace transform

                  java TraceCipher.java demo
                  java TraceCipher.java keygen  <keyfile>
                  java TraceCipher.java encrypt <keyfile> <input> <output>
                  java TraceCipher.java decrypt <keyfile> <input> <output>
                """);
    }

    private static byte[] readKey(String file) throws Exception {
        byte[] key = HexFormat.of().parseHex(Files.readString(Path.of(file)).trim());
        checkKey(key);
        return key;
    }

    private static void checkKey(byte[] key) throws GeneralSecurityException {
        if (key == null || key.length != KEY_BYTES) {
            throw new GeneralSecurityException("Key must be exactly " + KEY_BYTES + " bytes");
        }
    }

    private static int[] littleEndianWords(byte[] b) {
        int[] w = new int[b.length / 4];
        for (int i = 0; i < w.length; i++) {
            w[i] = (b[4 * i] & 0xFF) | (b[4 * i + 1] & 0xFF) << 8
                 | (b[4 * i + 2] & 0xFF) << 16 | (b[4 * i + 3] & 0xFF) << 24;
        }
        return w;
    }

    private static String bits(int v) {
        StringBuilder sb = new StringBuilder();
        for (int i = 7; i >= 0; i--) sb.append((v >>> i) & 1).append(' ');
        return sb.toString().trim();
    }
}
