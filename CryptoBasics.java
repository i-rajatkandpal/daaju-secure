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
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
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

    public static void testingWithSalt(){
        String password = "RajatKandpal";
        String salt1 = toBase64(generateRandomBytes(5));
        String salt2 = toBase64(generateRandomBytes(5));
        System.out.println(toBase64(sha256(password + salt1)));
        System.out.println(toBase64(sha256(password + salt2)));
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

    }
}
