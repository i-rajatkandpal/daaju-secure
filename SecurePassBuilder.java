public class SecurePassBuilder{
    private int iterations = 120_000;
    private int saltLength = 16;
    private int hashLength = 32;

    public SecurePassBuilder iterations(int iterations) {
        ValidationUtils.validateIterations(iterations);
        this.iterations = iterations;
        return this;
    }

    public SecurePassBuilder saltLength(int saltLength) {
        ValidationUtils.validateSaltLength(saltLength);
        this.saltLength = saltLength;
        return this;
    }

    public SecurePassBuilder hashLength(int hashLength) {
        ValidationUtils.validateHashLength(hashLength);
        this.hashLength = hashLength;
        return this;
    }

    public PasswordHashResult hash(String password) {
        ValidationUtils.validatePassword(password);
        return PBKDF2Hasher.hashPassword(password, iterations, saltLength, hashLength);
    }
}
