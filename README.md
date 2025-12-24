# 🔐 daaju-secure

daaju-secure is a lightweight Java library for secure password handling — hashing, verification, and validation — built using modern cryptographic best practices. It provides a simple and safe starting point for storing passwords correctly without reinventing crypto.

## ✨ Features
- PBKDF2-based password hashing
- Secure salt generation using SecureRandom
- Constant-time password verification
- Builder-style configuration API
- Password and input validation helpers
- Minimal, dependency-free Java code

## 📦 Project Structure
daaju-secure/
- PBKDF2Hasher.java
- SecurePass.java
- SecurePassBuilder.java
- CryptoBasics.java
- ValidationUtils.java
- PasswordHashResult.java

## 🚧 Status
- Early-stage / prototype
- No tests or CI yet
- No license file (recommended before public use)

## 🚀 Getting Started
Prerequisites:
- Java 8+ (Java 11+ recommended)

Compile (no build tool):
git clone https://github.com/i-rajatkandpal/daaju-secure.git
cd daaju-secure
javac -d out src/*.java

Adding Maven or Gradle is recommended for testing and dependency management.

## 🧠 Usage Examples (Conceptual)

PBKDF2 Hasher:
String password = "S3cur3P@ssw0rd!";
PBKDF2Hasher hasher = new PBKDF2Hasher();
PasswordHashResult result = hasher.hashPassword(password);
String stored = result.toEncodedString();
boolean verified = hasher.verifyPassword(password, stored);

SecurePass Builder:
SecurePass securePass = new SecurePassBuilder()
    .withIterations(150_000)
    .withSaltLength(16)
    .withAlgorithm("PBKDF2WithHmacSHA256")
    .build();
String hash = securePass.hash("password123");
boolean matches = securePass.verify("password123", hash);

## 🔐 Security Notes
- Uses Java SecretKeyFactory with PBKDF2
- Salt length ≥ 16 bytes
- High, configurable iteration count (100k+ recommended)
- Constant-time comparison to prevent timing attacks
- Avoid logging passwords, salts, or hashes
- Follow OWASP and NIST guidance for parameter updates

## 🛠️ Recommended Next Steps
- Add a LICENSE file (MIT / Apache-2.0)
- Add unit tests (PBKDF2 test vectors)
- Add Maven or Gradle build
- Configure GitHub Actions CI
- Run static analysis (SpotBugs / FindSecBugs)

## 🤝 Contributing
Fork the repository, make your changes, add tests where applicable, and open a pull request. Security-related changes should be well-documented.

## 👤 Author
Rajat Kandpal  
GitHub: https://github.com/i-rajatkandpal

## 📜 License
No license included yet. Add one before using this project in production.
