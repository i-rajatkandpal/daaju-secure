public class ValidationUtils {

    private static final int MIN_ITERATIONS = 1000;
    private static final int MAX_ITERATIONS = 10_000_000;
    private static final int MIN_SALT_LENGTH = 8;
    private static final int MAX_SALT_LENGTH = 128;
    private static final int MIN_HASH_LENGTH = 16;
    private static final int MAX_HASH_LENGTH = 512;
    private static final int MAX_PASSWORD_LENGTH = 1000;

    private ValidationUtils(){
    }

    public static void validatePassword(String password){
        if (password == null){
            throw new IllegalArgumentException("Password cannot be null");
        }
        if (password.isEmpty()){
            throw new IllegalArgumentException("Password cannot be empty");
        }
        if (password.length() > MAX_PASSWORD_LENGTH){
            throw new IllegalArgumentException(
                    String.format("Password too long (%d characters). Maximum: %d characters", password.length(), MAX_PASSWORD_LENGTH)
            );
        }
    }

    public static void validateIterations(int iterations) {
        if (iterations < MIN_ITERATIONS){
            throw new IllegalArgumentException(
                    String.format("Iterations too low (%d). Minimum: %d for security. " + "Recommended: 120,000+ (current OWASP standard)", iterations, MIN_ITERATIONS)
            );
        }
        if (iterations > MAX_ITERATIONS){
            throw new IllegalArgumentException(
                    String.format("Iterations too high (%d). Maximum: %d to prevent excessive delay", iterations, MAX_ITERATIONS)
            );
        }
    }

    public static void validateSalt(byte[] salt) {
        if (salt == null) {
            throw new IllegalArgumentException("Salt cannot be null");
        }
        validateSaltLength(salt.length);
    }

    public static void validateSaltLength(int saltLength) {
        if (saltLength < MIN_SALT_LENGTH){
            throw new IllegalArgumentException(
                    String.format("Salt length too short (%d bytes). Minimum: %d bytes (64 bits). " + "Recommended: 16 bytes (128 bits)", saltLength, MIN_SALT_LENGTH)
            );
        }
        if (saltLength > MAX_SALT_LENGTH){
            throw new IllegalArgumentException(
                    String.format("Salt length too large (%d bytes). Maximum: %d bytes " + "(no security benefit beyond this)", saltLength, MAX_SALT_LENGTH)
            );
        }
    }

    public static void validateHashLength(int hashLength) {
        if (hashLength < MIN_HASH_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Hash length too short (%d bytes). Minimum: %d bytes (128 bits). " + "Recommended: 32 bytes (256 bits)", hashLength, MIN_HASH_LENGTH)
            );
        }
        if (hashLength > MAX_HASH_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Hash length too large (%d bytes). Maximum: %d bytes (4096 bits)", hashLength, MAX_HASH_LENGTH)
            );
        }
    }

    public static void validateHash(byte[] hash) {
        if (hash == null) {
            throw new IllegalArgumentException("Hash cannot be null");
        }
        validateHashLength(hash.length);
    }

    public static void validateHashResult(PasswordHashResult result) {
        if (result == null) {
            throw new IllegalArgumentException("Hash result cannot be null");
        }
    }
}