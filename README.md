# CryptoSafe – Secure File Sharing (Java Swing + SQLite)

Desktop prototype: files are encrypted on your machine with **AES-256-GCM**, each file key is wrapped per recipient with **RSA-3072 OAEP (SHA-256)**, integrity is verified with **SHA-256**, and each user's RSA private key is stored encrypted under a **PBKDF2-HMAC-SHA256** key derived from the user's password.

**No database server needed.** Data is stored in an embedded SQLite file, so there is nothing to install except Java.

## Requirements
- JDK 17 or newer (check with `javac -version`)

The SQLite driver (`lib/sqlite-jdbc-*.jar`) is included in the repository.

## Run
- **Windows:** double-click `run.bat`
- **Linux / macOS:** `./run.sh`

Manual:
```bash
javac -encoding UTF-8 -cp "lib/*" -d out CryptoSafe.java
java -cp "out:lib/*" CryptoSafe        # on Windows use ;  instead of :
```

## Where data is stored
`~/CryptoSafeStorage/` (on Windows `C:\Users\<you>\CryptoSafeStorage\`):
- `cryptosafe.db` – users, file records, wrapped keys
- `encrypted/` – encrypted file blobs
- `downloads/` – default save location

Set the `CRYPTOSAFE_HOME` environment variable to use a different folder. Delete the folder to reset everything.

## How to use
1. **Create Account** – generates your RSA key pair (takes a few seconds).
2. **Upload File** – encrypts and stores it.
3. **My Files** – select a row, then *Decrypt / Download* or *Open*.
4. **Share / Revoke** – pick a file, enter the recipient's username. They see it under **Shared With Me**.
5. **Key Management** – shows your public-key fingerprint.

To try sharing, create two accounts (e.g. `alice` and `bob`), log out and in between.

## Implemented
Registration/login, PBKDF2 password hashing, RSA-3072 keys, encrypted private-key storage, AES-256-GCM file encryption, RSA-OAEP key wrapping, SHA-256 integrity check, sharing and revocation (owners cannot revoke themselves), authorised decrypt/download, prepared statements, random stored file names, 100 MB upload limit.

## Not implemented
Key rotation, audit log, digital signatures, share expiry/download limits, 2FA, rate limiting.

_College prototype – not production-hardened._
