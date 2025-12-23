public class SecurePass {
    private SecurePass(){
        //preventing instantiation
    }
    // simple hashing api
    public static PasswordHashResult hash(String password){
        return PBKDF2Hasher.hashPassword(password);
    }

    //verify
    public static boolean verify(String password, PasswordHashResult stored){
        return PBKDF2Hasher.verifyPassword(password,stored);
    }

    //advanced api
    public static SecurePassBuilder with(){
        return new SecurePassBuilder();
    }

    public static void main(String[] args) {
        PasswordHashResult a = SecurePass.hash("Rajat");
        PasswordHashResult b = SecurePass.with().iterations(150_000).saltLength(32).hashLength(64).hash("rajat");
        System.out.println(SecurePass.verify("rajat",a));
        System.out.println(SecurePass.verify("rajat",b));
    }

}
