import java.util.Base64;

public class PasswordHashResult {
    private final byte[] salt;
    private final byte[] hash;
    private final int iterations;

    public PasswordHashResult(byte[] salt, byte[] hash, int iterations) {
        ValidationUtils.validateSalt(salt);
        ValidationUtils.validateHash(hash);
        ValidationUtils.validateIterations(iterations);
        this.salt = salt.clone();  // Defensive copy
        this.hash = hash.clone();  // Defensive copy
        this.iterations = iterations;
    }

    public byte[] getSalt() {
        return salt.clone();  // Defensive copy
    }

    public byte[] getHash() {
        return hash.clone();  // Defensive copy
    }

    public int getIterations() {
        return iterations;
    }

    @Override
    public String toString() {
        String saltB64 = Base64.getEncoder().encodeToString(this.salt);
        String hashB64 = Base64.getEncoder().encodeToString(this.hash);

        return String.format(
                "$pbkdf2-sha256$i=%d$%s$%s",
                this.iterations,
                saltB64,
                hashB64
        );
    }

    public static PasswordHashResult fromString(String storedHash) {
        // Split the string by '$'
        // Format: $pbkdf2-sha256$i=120000$<base64-salt>$<base64-hash>
        String[] parts = storedHash.split("\\$");

        if (parts.length != 5) {
            throw new IllegalArgumentException("Invalid stored hash format");
        }

        // parts[0] is empty (because string starts with $)
        // parts[1] = algorithm (should be "pbkdf2-sha256")
        // parts[2] = iterations like "i=120000"
        // parts[3] = Base64-encoded salt
        // parts[4] = Base64-encoded hash

        if (!"pbkdf2-sha256".equals(parts[1])) {
            throw new IllegalArgumentException("Unsupported algorithm: " + parts[1]);
        }

        // Parse iterations
        if (!parts[2].startsWith("i=")) {
            throw new IllegalArgumentException("Invalid iteration format: " + parts[2]);
        }
        int iterations = Integer.parseInt(parts[2].substring(2));

        // Decode salt and hash from Base64
        byte[] salt = Base64.getDecoder().decode(parts[3]);
        byte[] hash = Base64.getDecoder().decode(parts[4]);

        return new PasswordHashResult(salt, hash, iterations);
    }

}
