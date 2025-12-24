public class SecurePass {
    private SecurePass(){
        //preventing instantiation
    }
    // simple hashing api
    public static PasswordHashResult hash(String password){
        ValidationUtils.validatePassword(password);
        return PBKDF2Hasher.hashPassword(password);
    }

    //verify
    public static boolean verify(String password, PasswordHashResult stored){
        ValidationUtils.validatePassword(password);
        ValidationUtils.validateHashResult(stored);
        return PBKDF2Hasher.verifyPassword(password,stored);
    }

    //advanced api
    public static SecurePassBuilder with(){
        return new SecurePassBuilder();
    }

//    public static void main(String[] args) {
//        PasswordHashResult a = SecurePass.hash("Rajat");
//        PasswordHashResult b = SecurePass.with().iterations(150_000).saltLength(32).hashLength(64).hash("rajat");
//        System.out.println(SecurePass.verify("rajat",a));
//        System.out.println(SecurePass.verify("rajat",b));
//    }

    public static void main(String[] args) {
        System.out.println("=== SecurePass Test ===\n");

        // Test 1: Simple API
        System.out.println("Test 1: Simple hash");
        PasswordHashResult a = SecurePass.hash("Rajat");
        System.out.println("Hash: " + a.toString());
        System.out.println("Verify 'Rajat': " + SecurePass.verify("Rajat", a)); // ← Match case
        System.out.println("Verify 'rajat': " + SecurePass.verify("rajat", a)); // ← Should be false
        System.out.println();

        // Test 2: Custom config
        System.out.println("Test 2: Custom config");
        PasswordHashResult b = SecurePass.with()
                .iterations(150_000)
                .saltLength(32)
                .hashLength(64)
                .hash("rajat");
        System.out.println("Hash: " + b.toString());
        System.out.println("Verify 'rajat': " + SecurePass.verify("rajat", b));
        System.out.println("Verify 'wrong': " + SecurePass.verify("wrong", b));
        System.out.println();

        // Test 3: Same password, different hashes
        System.out.println("Test 3: Different salts");
        PasswordHashResult c1 = SecurePass.hash("password");
        PasswordHashResult c2 = SecurePass.hash("password");
        System.out.println("Hash 1: " + c1.toString());
        System.out.println("Hash 2: " + c2.toString());
        System.out.println("Are different: " + !c1.toString().equals(c2.toString()));
        System.out.println();

        // Test 4: Performance
        System.out.println("Test 4: Performance");
        long start = System.currentTimeMillis();
        SecurePass.hash("test");
        System.out.println("Default (120K): " + (System.currentTimeMillis() - start) + "ms");

        start = System.currentTimeMillis();
        SecurePass.with().iterations(200_000).hash("test");
        System.out.println("Custom (200K): " + (System.currentTimeMillis() - start) + "ms");
    }

}
