import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Arrays;

public class CryptoBasics {
    public static byte[] generateRandomBytes(int length){
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes); // nextBytes() uses OS entropy, but generateSeed() skips it.
        return bytes;
    }

    public static byte[] sha256(String input){
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8); //converts string into byte (digest happens only in bytes)
            byte[] hashBytes = md.digest(inputBytes);
            return hashBytes;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 hashing failed", e);
        }
    }
    public static String toBase64(byte[] bytes){
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(bytes);
    }

    public static byte[]  fromBase64(String base64String){
        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(base64String);
    }

    public static void testingWithoutSalt(){
        String password = "RajatKandpal";
        String hash1 = toBase64(sha256(password));
        String hash2 = toBase64(sha256(password));

        System.out.println(hash1 + "  ||||  " + hash2);
    }

    public static void testingWithSalt() {
        try {
            String password = "RajatKandpal";

            byte[] salt1 = generateRandomBytes(16);
            byte[] salt2 = generateRandomBytes(16);

            // First hash
            MessageDigest md1 = MessageDigest.getInstance("SHA-256");
            md1.update(password.getBytes(StandardCharsets.UTF_8)); //md has a buffer, first password byte is added
            md1.update(salt1);// then salt byte
            byte[] hash1 = md1.digest();

            // Second hash
            MessageDigest md2 = MessageDigest.getInstance("SHA-256");
            md2.update(password.getBytes(StandardCharsets.UTF_8));
            md2.update(salt2);
            byte[] hash2 = md2.digest();

            System.out.println(toBase64(hash1));
            System.out.println(toBase64(hash2));

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

        public static void measuringHashingSpeed(){
        long attempts = 100_000;
        long currTime = System.currentTimeMillis();

        String password = "RajatKandpal";
        for(int i = 0; i<attempts; i++){
            sha256(password);
        }

        System.out.println(System.currentTimeMillis() - currTime);
    }

    public static void main(String[] args) {
        testingWithSalt();
    }
}
