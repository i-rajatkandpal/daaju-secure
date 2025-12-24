import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

public class PBKDF2Hasher {
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 120_000;
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;

    public static PasswordHashResult hashPassword(String password){

        try {
            byte[] salt = CryptoBasics.generateRandomBytes(SALT_LENGTH);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, HASH_LENGTH * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            spec.clearPassword();

            return new PasswordHashResult(salt, hash, ITERATIONS);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Error while Hashing");
        }
    }

    // with specific salt and iterations
    //but default hash_length

    public static byte[] hashPassword(String password, byte[] salt , int iterations){
        ValidationUtils.validatePassword(password);
        ValidationUtils.validateSalt(salt);
        ValidationUtils.validateIterations(iterations);
        char[] chars = password.toCharArray();
        try{
            PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, HASH_LENGTH * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        finally{
            Arrays.fill(chars,'\0');
        }
    }

    //with specific salt and iteration
    //but with custom hash_length

    public static byte[] hashPassword(String password, byte[] salt, int iterations, int hashLength) {
        char[] chars = password.toCharArray();
        try {
            PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, hashLength * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    public static PasswordHashResult hashPassword(String password, int iterations, int saltLength,int hashLength) {
        byte[] salt = CryptoBasics.generateRandomBytes(saltLength);
        byte[] hash = hashPassword(password, salt, iterations, hashLength);
        return new PasswordHashResult(salt, hash, iterations);
    }


    public static boolean verifyPassword(String password, PasswordHashResult storedResult){
        byte[] computed;
        if(storedResult.getHash().length == HASH_LENGTH){
            computed = hashPassword(password, storedResult.getSalt(), storedResult.getIterations());
        }
        else{
            computed = hashPassword(password, storedResult.getSalt(), storedResult.getIterations(), storedResult.getHash().length);
        }
        boolean matched = constantTimeComparison(computed,storedResult.getHash());
        Arrays.fill(computed,(byte) 0);
        return matched;
    }

    public static boolean constantTimeComparison(byte[] A, byte[] B) {
        if(A.length != B.length) return false;
        int res = 0;
        for(int i = 0; i<A.length; i++){
            res |= A[i] ^ B[i];
        }
        return res == 0;
    }
}

