import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Arrays;

/** Demonstrates the XOR operation for a one-time-pad-style exercise. */
public class OneTimePadDemo {
    public static void main(String[] args) {
        String plaintext = "MY NAME IS UNKNOWN";
        byte[] input = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] pad = new byte[input.length];
        new SecureRandom().nextBytes(pad);
        byte[] ciphertext = xor(input, pad);
        byte[] recovered = xor(ciphertext, pad);
        System.out.println("Plaintext : " + plaintext);
        System.out.println("Bytes     : " + input.length);
        System.out.println("Key (hex) : " + HexFormat.of().formatHex(pad));
        System.out.println("Cipher(hex): " + HexFormat.of().formatHex(ciphertext));
        System.out.println("Decrypted : " + new String(recovered, StandardCharsets.UTF_8));
        System.out.println("Round-trip verified: " + Arrays.equals(input, recovered));
        Arrays.fill(pad, (byte) 0); // best-effort cleanup of this Java array
    }
    private static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) throw new IllegalArgumentException("Equal lengths required");
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }
}
