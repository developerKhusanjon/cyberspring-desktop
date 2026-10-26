# CyberSpring Vulnerability & SAST Audit Report

**Target Path:** `test_samples/vulnerable_app`  
**Scanned Files:** 3 | **Total Lines:** 85 | **Scan Time:** 0ms  
**Total Findings:** 9 (Critical: 4, High: 3, Medium: 2, Low: 0)

## Findings Breakdown

### 1. [CRITICAL] Hardcoded AWS Access Key
- **Location:** `test_samples/vulnerable_app/cloud_storage.py:5`
- **CWE / OWASP:** `CWE-798` | `A07:2021-Identification and Authentication Failures`
- **Description:** Hardcoded AWS Access Key ID exposed in source code. Can lead to unauthorized cloud infrastructure takeover.
- **Remediation:** Store AWS credentials in environment variables or use IAM roles / AWS Secrets Manager.

```diff
- os.Setenv("AWS_KEY", "AKIAIOSFODNN7EXAMPLE")
+ awsKey := os.Getenv("AWS_ACCESS_KEY_ID")
```

### 2. [CRITICAL] Command Injection / Shell Execution
- **Location:** `test_samples/vulnerable_app/cloud_storage.py:11`
- **CWE / OWASP:** `CWE-78` | `A03:2021-Injection`
- **Description:** Command passed to system shell execution (`sh -c`, `os.system`, `subprocess(..., shell=True)`). Unsanitized input can execute arbitrary commands.
- **Remediation:** Execute specific binaries directly with explicit arguments without spawning a shell interpreter.

```diff
- exec.Command("sh", "-c", userInput)
+ exec.Command("/usr/bin/safe-binary", "--arg", validatedInput)
```

### 3. [CRITICAL] Command Injection / Shell Execution
- **Location:** `test_samples/vulnerable_app/cloud_storage.py:14`
- **CWE / OWASP:** `CWE-78` | `A03:2021-Injection`
- **Description:** Command passed to system shell execution (`sh -c`, `os.system`, `subprocess(..., shell=True)`). Unsanitized input can execute arbitrary commands.
- **Remediation:** Execute specific binaries directly with explicit arguments without spawning a shell interpreter.

```diff
- exec.Command("sh", "-c", userInput)
+ exec.Command("/usr/bin/safe-binary", "--arg", validatedInput)
```

### 4. [MEDIUM] Overly Permissive CORS Policy
- **Location:** `test_samples/vulnerable_app/file_handler.js:7`
- **CWE / OWASP:** `CWE-942` | `A05:2021-Security Misconfiguration`
- **Description:** Access-Control-Allow-Origin header set to wildcard `*` with credentials or sensitive endpoints.
- **Remediation:** Explicitly specify allowed trusted origins rather than wildcard.

```diff
- w.Header().Set("Access-Control-Allow-Origin", "*")
+ w.Header().Set("Access-Control-Allow-Origin", "https://app.corp.internal")
```

### 5. [HIGH] Path Traversal Weakness
- **Location:** `test_samples/vulnerable_app/file_handler.js:15`
- **CWE / OWASP:** `CWE-22` | `A01:2021-Broken Access Control`
- **Description:** File opened directly with filepath concatenation without validating if the resolved path stays within the base directory.
- **Remediation:** Sanitize path using `filepath.Clean` and ensure `strings.HasPrefix(targetPath, baseDir)` before opening.

```diff
- os.Open(filepath.Join(baseDir, userFilename))
+ cleanPath := filepath.Clean(filepath.Join(baseDir, userFilename))
+ if !strings.HasPrefix(cleanPath, baseDir) { return ErrInvalidPath }
```

### 6. [HIGH] SQL Injection via String Concatenation
- **Location:** `test_samples/vulnerable_app/auth_service.go:20`
- **CWE / OWASP:** `CWE-89` | `A03:2021-Injection`
- **Description:** Dynamic SQL query formed with string concatenation or string formatting without parameterized queries.
- **Remediation:** Use parameterized queries (e.g. `db.Query("SELECT ... WHERE id = ?", id)`).

```diff
- db.Query("SELECT * FROM users WHERE name = '" + username + "'")
+ db.Query("SELECT * FROM users WHERE name = ?", username)
```

### 7. [MEDIUM] Broken or Weak Cryptographic Hash (MD5 / SHA-1)
- **Location:** `test_samples/vulnerable_app/auth_service.go:29`
- **CWE / OWASP:** `CWE-328` | `A02:2021-Cryptographic Failures`
- **Description:** Usage of MD5 or SHA-1 for cryptographic security or password hashing. Both algorithms suffer from collision attacks.
- **Remediation:** Upgrade to SHA-256 (`crypto/sha256`), Argon2id, or bcrypt for passwords.

```diff
- h := md5.New()
+ h := sha256.New()
```

### 8. [CRITICAL] Command Injection / Shell Execution
- **Location:** `test_samples/vulnerable_app/auth_service.go:38`
- **CWE / OWASP:** `CWE-78` | `A03:2021-Injection`
- **Description:** Command passed to system shell execution (`sh -c`, `os.system`, `subprocess(..., shell=True)`). Unsanitized input can execute arbitrary commands.
- **Remediation:** Execute specific binaries directly with explicit arguments without spawning a shell interpreter.

```diff
- exec.Command("sh", "-c", userInput)
+ exec.Command("/usr/bin/safe-binary", "--arg", validatedInput)
```

### 9. [HIGH] TLS Certificate Verification Disabled
- **Location:** `test_samples/vulnerable_app/auth_service.go:46`
- **CWE / OWASP:** `CWE-295` | `A05:2021-Security Misconfiguration`
- **Description:** `InsecureSkipVerify: true` or `verify=False` disables SSL/TLS certificate validation, enabling Man-in-the-Middle (MITM) attacks.
- **Remediation:** Never disable TLS verification in production. Install and trust required Root CAs instead.

```diff
- &tls.Config{InsecureSkipVerify: true}
+ &tls.Config{InsecureSkipVerify: false, RootCAs: caPool}
```

