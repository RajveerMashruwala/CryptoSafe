import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.sql.*;
import java.util.*;
import java.util.List;
import java.util.Base64;

/*
 * CryptoSafe - Single File Working Prototype (Java Swing + embedded SQLite)
 * See README.md for setup. No database server is required.
 */
public class CryptoSafe {
    // ===================== DATABASE CONFIG =====================
    // Embedded SQLite database - no server or installation needed.
    // Stored next to the encrypted files in ~/CryptoSafeStorage/cryptosafe.db
    // (override the folder with the CRYPTOSAFE_HOME environment variable).

    // ===================== APPLICATION CONFIG ==================
    static final Path STORAGE = Paths.get(System.getenv("CRYPTOSAFE_HOME") != null
            ? System.getenv("CRYPTOSAFE_HOME")
            : System.getProperty("user.home") + java.io.File.separator + "CryptoSafeStorage");
    static final Path DB_FILE = STORAGE.resolve("cryptosafe.db");
    static final String DB_URL = "jdbc:sqlite:" + DB_FILE.toAbsolutePath() + "?foreign_keys=on&busy_timeout=5000";
    static final Path ENCRYPTED_FILES = STORAGE.resolve("encrypted");
    static final Path DOWNLOADS = STORAGE.resolve("downloads");

    static final Color PRIMARY = Color.decode("#3F5F8A");
    static final Color ACCENT_LIGHT_ALT = Color.decode("#E8EEF5");
    static final Color BACKGROUND = Color.decode("#F5F7FA");
    static final Color ACCENT_DARK_ALT = Color.decode("#2B3A4F");
    static final Color TEXT = Color.decode("#2B3440");

    static UserSession session;

    // ===================== ENTRY POINT =========================
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } catch (Exception ignored) {}
            installModernLook();
            try {
                ensureStorage();
            } catch (IOException e) {
                fatal("Cannot create the storage folder:\n" + STORAGE + "\n\n" + e.getMessage());
                return;
            }
            String dbError = Database.initialize();
            if (dbError != null) { fatal(dbError); return; }
            new LoginFrame().setVisible(true);
        });
    }
    static void ensureStorage() throws IOException {
        Files.createDirectories(ENCRYPTED_FILES);
        Files.createDirectories(DOWNLOADS);
    }
    static void fatal(String msg) {
        JOptionPane.showMessageDialog(null, msg, "CryptoSafe - cannot start", JOptionPane.ERROR_MESSAGE);
        System.exit(1);
    }


    // ===================== DATABASE ============================
    static class Database {
        static Connection getConnection() throws SQLException {
            return DriverManager.getConnection(DB_URL);
        }
        /** Creates the tables if needed. Returns null on success, or an error message. */
        static String initialize() {
            String[] sql = {
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    private_key_enc TEXT NOT NULL,
                    private_key_iv TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL,
                    original_name TEXT NOT NULL,
                    stored_name TEXT NOT NULL UNIQUE,
                    encrypted_path TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS file_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    wrapped_key TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
                    shared_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(file_id, user_id),
                    FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            };
            try {
                Class.forName("org.sqlite.JDBC");
                try (Connection c = getConnection(); Statement st = c.createStatement()) {
                    for (String q : sql) st.executeUpdate(q);
                }
            } catch (ClassNotFoundException e) {
                return "The SQLite driver was not found.\n\nPut sqlite-jdbc-*.jar in the lib/ folder\n"
                     + "and start the app with run.bat / run.sh.";
            } catch (Exception e) {
                return "Could not open the database file:\n" + DB_FILE + "\n\n" + e.getMessage();
            }
            return null;
        }
    }

    // ===================== SECURITY ============================
    static class Crypto {
        static final SecureRandom RANDOM = new SecureRandom();

        static byte[] random(int n) {
            byte[] b = new byte[n];
            RANDOM.nextBytes(b);
            return b;
        }

        static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
        static byte[] unb64(String s) { return Base64.getDecoder().decode(s); }

        static byte[] pbkdf2(char[] password, byte[] salt) throws Exception {
            PBEKeySpec spec = new PBEKeySpec(password, salt, 210_000, 256);
            try {
                return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                        .generateSecret(spec).getEncoded();
            } finally { spec.clearPassword(); }
        }

        static String passwordHash(char[] password, byte[] salt) throws Exception {
            return b64(pbkdf2(password, salt));
        }

        static boolean verifyPassword(char[] password, String stored, String salt) throws Exception {
            byte[] actual = pbkdf2(password, unb64(salt));
            byte[] expected = unb64(stored);
            return MessageDigest.isEqual(actual, expected);
        }

        static KeyPair generateRSA() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(3072, RANDOM);
            return kpg.generateKeyPair();
        }

        static byte[] aesEncrypt(byte[] plain, byte[] key, byte[] iv, byte[] aad) throws Exception {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv));
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(plain);
        }

        static byte[] aesDecrypt(byte[] cipher, byte[] key, byte[] iv, byte[] aad) throws Exception {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv));
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(cipher);
        }

        static byte[] rsaWrap(byte[] aesKey, PublicKey publicKey) throws Exception {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            OAEPParameterSpec oaep = new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            c.init(Cipher.ENCRYPT_MODE, publicKey, oaep);
            return c.doFinal(aesKey);
        }

        static byte[] rsaUnwrap(byte[] wrapped, PrivateKey privateKey) throws Exception {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            OAEPParameterSpec oaep = new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            c.init(Cipher.DECRYPT_MODE, privateKey, oaep);
            return c.doFinal(wrapped);
        }

        static String sha256(byte[] data) throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return hex(md.digest(data));
        }

        static String sha256File(Path path) throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream in = Files.newInputStream(path)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) md.update(buf, 0, n);
            }
            return hex(md.digest());
        }

        static String hex(byte[] b) {
            StringBuilder sb = new StringBuilder();
            for (byte x : b) sb.append(String.format("%02x", x));
            return sb.toString();
        }

        /*
         * Private RSA key is encrypted before it is stored in the database.
         * The AES key is derived from the user's password using PBKDF2.
         */
        static PrivateKey decryptPrivateKey(String enc, String iv, char[] password) throws Exception {
            byte[] salt = unb64(iv); // first 16 bytes are salt, remaining 12 are GCM IV
            byte[] salt16 = Arrays.copyOfRange(salt, 0, 16);
            byte[] gcmIv = Arrays.copyOfRange(salt, 16, 28);
            byte[] key = pbkdf2(password, salt16);
            byte[] raw = aesDecrypt(unb64(enc), key, gcmIv, null);
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(raw));
        }

        static EncryptedPrivate encryptPrivateKey(PrivateKey pk, char[] password) throws Exception {
            byte[] salt = random(16);
            byte[] gcmIv = random(12);
            byte[] key = pbkdf2(password, salt);
            byte[] enc = aesEncrypt(pk.getEncoded(), key, gcmIv, null);
            byte[] packed = new byte[28];
            System.arraycopy(salt, 0, packed, 0, 16);
            System.arraycopy(gcmIv, 0, packed, 16, 12);
            return new EncryptedPrivate(b64(enc), b64(packed));
        }
    }

    static class EncryptedPrivate {
        String ciphertext, packedIv;
        EncryptedPrivate(String c, String i) { ciphertext=c; packedIv=i; }
    }

    // ===================== USER SESSION ========================
    static class UserSession {
        int id;
        String username, email;
        PrivateKey privateKey;
        UserSession(int id, String username, String email, PrivateKey privateKey) {
            this.id=id; this.username=username; this.email=email; this.privateKey=privateKey;
        }
    }

    // ===================== AUTH SERVICE ========================
    static class Auth {
        static boolean register(String username, String email, char[] password) throws Exception {
            if (!username.matches("[A-Za-z0-9_]{3,80}")) throw new Exception("Username: 3-80 letters, numbers or underscore.");
            if (!email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")) throw new Exception("Enter a valid email.");
            if (password.length < 8) throw new Exception("Password must be at least 8 characters.");

            byte[] salt = Crypto.random(16);
            String hash = Crypto.passwordHash(password, salt);
            KeyPair kp = Crypto.generateRSA();
            EncryptedPrivate ep = Crypto.encryptPrivateKey(kp.getPrivate(), password);

            String q = "INSERT INTO users(username,email,password_hash,password_salt,public_key,private_key_enc,private_key_iv) VALUES(?,?,?,?,?,?,?)";
            try (Connection c=Database.getConnection(); PreparedStatement p=c.prepareStatement(q)) {
                p.setString(1,username); p.setString(2,email);
                p.setString(3,hash); p.setString(4,Crypto.b64(salt));
                p.setString(5,Crypto.b64(kp.getPublic().getEncoded()));
                p.setString(6,ep.ciphertext); p.setString(7,ep.packedIv);
                p.executeUpdate();
                return true;
            } catch (SQLException e) {
                if (e.getMessage().toLowerCase().matches("(?s).*(duplicate|unique constraint).*"))
                    throw new Exception("Username or email already exists.");
                throw e;
            }
        }

        static UserSession login(String username, char[] password) throws Exception {
            String q="SELECT * FROM users WHERE username=?";
            try (Connection c=Database.getConnection(); PreparedStatement p=c.prepareStatement(q)) {
                p.setString(1,username);
                try(ResultSet r=p.executeQuery()) {
                    if(!r.next()) throw new Exception("Invalid username or password.");
                    if(!Crypto.verifyPassword(password,r.getString("password_hash"),r.getString("password_salt")))
                        throw new Exception("Invalid username or password.");
                    PrivateKey pk=Crypto.decryptPrivateKey(r.getString("private_key_enc"),r.getString("private_key_iv"),password);
                    return new UserSession(r.getInt("id"),r.getString("username"),r.getString("email"),pk);
                }
            }
        }

        static PublicKey getPublicKey(int userId) throws Exception {
            try(Connection c=Database.getConnection(); PreparedStatement p=c.prepareStatement("SELECT public_key FROM users WHERE id=?")){
                p.setInt(1,userId);
                try(ResultSet r=p.executeQuery()){
                    if(!r.next()) throw new Exception("User not found.");
                    return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Crypto.unb64(r.getString(1))));
                }
            }
        }
    }

    // ===================== FILE SERVICE ========================
    static class FileService {
        static long upload(Path source) throws Exception {
            if(Files.size(source)>100L*1024*1024) throw new Exception("File is too large (limit 100 MB).");
            byte[] plain=Files.readAllBytes(source);
            byte[] aesKey=Crypto.random(32);
            byte[] iv=Crypto.random(12);
            String hash=Crypto.sha256(plain);
            byte[] aad=(source.getFileName()+"|"+hash).getBytes(StandardCharsets.UTF_8);
            byte[] encrypted=Crypto.aesEncrypt(plain,aesKey,iv,aad);

            String stored=UUID.randomUUID().toString()+".cfs";
            Files.createDirectories(ENCRYPTED_FILES);
            Path target=ENCRYPTED_FILES.resolve(stored).normalize();
            if(!target.getParent().equals(ENCRYPTED_FILES.toAbsolutePath().normalize()))
                throw new SecurityException("Invalid storage path.");
            Files.write(target,encrypted,StandardOpenOption.CREATE_NEW);

            String q="INSERT INTO files(owner_id,original_name,stored_name,encrypted_path,iv,sha256,size_bytes) VALUES(?,?,?,?,?,?,?)";
            long id;
            try(Connection c=Database.getConnection(); PreparedStatement p=c.prepareStatement(q,Statement.RETURN_GENERATED_KEYS)){
                p.setInt(1,session.id); p.setString(2,source.getFileName().toString());
                p.setString(3,stored); p.setString(4,target.toString());
                p.setString(5,Crypto.b64(iv)); p.setString(6,hash); p.setLong(7,plain.length);
                p.executeUpdate();
                try(ResultSet rs=p.getGeneratedKeys()){rs.next(); id=rs.getLong(1);}
            }

            PublicKey ownerPub=Auth.getPublicKey(session.id);
            byte[] wrapped=Crypto.rsaWrap(aesKey,ownerPub);
            try(Connection c=Database.getConnection(); PreparedStatement p=c.prepareStatement(
                    "INSERT INTO file_keys(file_id,user_id,wrapped_key,status) VALUES(?,?,?,'ACTIVE')")){
                p.setLong(1,id);p.setInt(2,session.id);p.setString(3,Crypto.b64(wrapped));p.executeUpdate();
            }
            Arrays.fill(aesKey,(byte)0);
            return id;
        }

        static List<Object[]> myFiles() throws Exception {
            List<Object[]> out=new ArrayList<>();
            String q="SELECT id,original_name,size_bytes,sha256,created_at FROM files WHERE owner_id=? ORDER BY id DESC";
            try(Connection c=Database.getConnection();PreparedStatement p=c.prepareStatement(q)){
                p.setInt(1,session.id);
                try(ResultSet r=p.executeQuery()){
                    while(r.next()) out.add(new Object[]{r.getLong(1),r.getString(2),r.getLong(3),r.getString(4),r.getString(5)});
                }
            }
            return out;
        }

        static List<Object[]> sharedFiles() throws Exception {
            List<Object[]> out=new ArrayList<>();
            String q="""
                SELECT f.id,f.original_name,u.username,k.status,k.shared_at
                FROM file_keys k JOIN files f ON k.file_id=f.id
                JOIN users u ON f.owner_id=u.id
                WHERE k.user_id=? AND k.status='ACTIVE' AND f.owner_id<>?
                ORDER BY k.shared_at DESC
            """;
            try(Connection c=Database.getConnection();PreparedStatement p=c.prepareStatement(q)){
                p.setInt(1,session.id);p.setInt(2,session.id);
                try(ResultSet r=p.executeQuery()){
                    while(r.next()) out.add(new Object[]{r.getLong(1),r.getString(2),r.getString(3),r.getString(4),r.getString(5)});
                }
            }
            return out;
        }

        static void share(long fileId,String recipient) throws Exception {
            if(recipient.equalsIgnoreCase(session.username)) throw new Exception("You already own this file.");
            int uid;
            try(Connection c=Database.getConnection();PreparedStatement p=c.prepareStatement("SELECT id FROM users WHERE username=?")){
                p.setString(1,recipient);
                try(ResultSet r=p.executeQuery()){if(!r.next()) throw new Exception("Recipient user not found."); uid=r.getInt(1);}
            }

            String q="SELECT stored_name,iv FROM files WHERE id=? AND owner_id=?";
            String fileName,iv;
            try(Connection c=Database.getConnection();PreparedStatement p=c.prepareStatement(q)){
                p.setLong(1,fileId);p.setInt(2,session.id);
                try(ResultSet r=p.executeQuery()){if(!r.next())throw new Exception("File not found or not owned by you.");fileName=r.getString(1);iv=r.getString(2);}
            }

            byte[] aesKey=getOwnerAESKey(fileId,iv);
            PublicKey pub=Auth.getPublicKey(uid);
            byte[] wrapped=Crypto.rsaWrap(aesKey,pub);

            try(Connection c=Database.getConnection();PreparedStatement p=c.prepareStatement(
                    "INSERT INTO file_keys(file_id,user_id,wrapped_key,status) VALUES(?,?,?,'ACTIVE') ON CONFLICT(file_id,user_id) DO UPDATE SET wrapped_key=excluded.wrapped_key,status='ACTIVE',shared_at=CURRENT_TIMESTAMP")){
                p.setLong(1,fileId);p.setInt(2,uid);p.setString(3,Crypto.b64(wrapped));p.executeUpdate();
            }
            Arrays.fill(aesKey,(byte)0);
        }

        static byte[] getOwnerAESKey(long fileId,String ivString) throws Exception {
            String q="SELECT wrapped_key FROM file_keys WHERE file_id=? AND user_id=? AND status='ACTIVE'";
            try(Connection c=Database.getConnection();PreparedStatement p=c.prepareStatement(q)){
                p.setLong(1,fileId);p.setInt(2,session.id);
                try(ResultSet r=p.executeQuery()){
                    if(!r.next()) throw new Exception("No authorized key found.");
                    return Crypto.rsaUnwrap(Crypto.unb64(r.getString(1)),session.privateKey);
                }
            }
        }

        static void revoke(long fileId,String username) throws Exception {
            if(username.equalsIgnoreCase(session.username)) throw new Exception("You cannot revoke your own access to your file.");
            String q="""
                UPDATE file_keys SET status='REVOKED'
                WHERE file_id=?
                  AND user_id=(SELECT id FROM users WHERE username=?)
                  AND file_id IN (SELECT id FROM files WHERE owner_id=?)
            """;
            try(Connection c=Database.getConnection();PreparedStatement p=c.prepareStatement(q)){
                p.setLong(1,fileId);p.setString(2,username);p.setInt(3,session.id);
                if(p.executeUpdate()==0) throw new Exception("No active share found for that user.");
            }
        }

        static Path decryptToFile(long fileId, boolean shared, Path dest) throws Exception {
            String q;
            if(shared) q="""
                SELECT f.original_name,f.encrypted_path,f.iv,f.sha256,k.wrapped_key
                FROM files f JOIN file_keys k ON f.id=k.file_id
                WHERE f.id=? AND k.user_id=? AND k.status='ACTIVE'
            """;
            else q="""
                SELECT f.original_name,f.encrypted_path,f.iv,f.sha256,k.wrapped_key
                FROM files f JOIN file_keys k ON f.id=k.file_id
                WHERE f.id=? AND f.owner_id=? AND k.user_id=? AND k.status='ACTIVE'
            """;

            String name,path,iv,hash,wrapped;
            try(Connection c=Database.getConnection();PreparedStatement p=c.prepareStatement(q)){
                p.setLong(1,fileId);
                if(shared){
                    p.setInt(2,session.id);
                } else {
                    p.setInt(2,session.id);
                    p.setInt(3,session.id);
                }
                try(ResultSet r=p.executeQuery()){
                    if(!r.next())throw new SecurityException("Unauthorized file access.");
                    name=r.getString(1);
                    path=r.getString(2);
                    iv=r.getString(3);
                    hash=r.getString(4);
                    wrapped=r.getString(5);
                }
            }

            byte[] aesKey=Crypto.rsaUnwrap(
                    Crypto.unb64(wrapped),
                    session.privateKey
            );
            try {
                byte[] encrypted=Files.readAllBytes(
                        Paths.get(path).normalize()
                );
                byte[] aad=(name+"|"+hash).getBytes(StandardCharsets.UTF_8);
                byte[] plain=Crypto.aesDecrypt(
                        encrypted,
                        aesKey,
                        Crypto.unb64(iv),
                        aad
                );

                String actual=Crypto.sha256(plain);
                if(!MessageDigest.isEqual(
                        actual.getBytes(StandardCharsets.UTF_8),
                        hash.getBytes(StandardCharsets.UTF_8)
                ))
                    throw new SecurityException("Integrity verification failed.");

                Path safeDest=dest.toAbsolutePath().normalize();
                Files.write(
                        safeDest,
                        plain,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE
                );
                return safeDest;
            } finally {
                Arrays.fill(aesKey,(byte)0);
            }
        }

        static Path download(long fileId,boolean shared) throws Exception {
            String q;
            if(shared) q="""
                SELECT f.original_name,f.encrypted_path,f.iv,f.sha256,k.wrapped_key
                FROM files f JOIN file_keys k ON f.id=k.file_id
                WHERE f.id=? AND k.user_id=? AND k.status='ACTIVE'
            """;
            else q="""
                SELECT f.original_name
                FROM files f JOIN file_keys k ON f.id=k.file_id
                WHERE f.id=? AND f.owner_id=? AND k.user_id=? AND k.status='ACTIVE'
            """;
            String name;
            try(Connection c=Database.getConnection();PreparedStatement p=c.prepareStatement(q)){
                p.setLong(1,fileId);
                if(shared){
                    p.setInt(2,session.id);
                } else {
                    p.setInt(2,session.id);
                    p.setInt(3,session.id);
                }
                try(ResultSet r=p.executeQuery()){
                    if(!r.next())throw new SecurityException("Unauthorized file access.");
                    name=r.getString(1);
                }
            }

            JFileChooser fc=new JFileChooser(DOWNLOADS.toFile());
            fc.setSelectedFile(new File(name));
            if(fc.showSaveDialog(null)!=JFileChooser.APPROVE_OPTION)return null;
            Path dest=fc.getSelectedFile().toPath().toAbsolutePath().normalize();
            if(!dest.startsWith(DOWNLOADS.toAbsolutePath().normalize()) && !confirm("Save outside CryptoSafe Downloads?"))
                return null;

            Path saved=decryptToFile(fileId,shared,dest);


            return saved;
        }

        static void open(long fileId, boolean shared) throws Exception {
            String q;
            if(shared) q="""
                SELECT f.original_name
                FROM files f JOIN file_keys k ON f.id=k.file_id
                WHERE f.id=? AND k.user_id=? AND k.status='ACTIVE'
            """;
            else q="""
                SELECT f.original_name
                FROM files f JOIN file_keys k ON f.id=k.file_id
                WHERE f.id=? AND f.owner_id=? AND k.user_id=? AND k.status='ACTIVE'
            """;

            String name;
            try(Connection c=Database.getConnection();PreparedStatement p=c.prepareStatement(q)){
                p.setLong(1,fileId);
                if(shared){
                    p.setInt(2,session.id);
                } else {
                    p.setInt(2,session.id);
                    p.setInt(3,session.id);
                }
                try(ResultSet r=p.executeQuery()){
                    if(!r.next())throw new SecurityException("Unauthorized file access.");
                    name=r.getString(1);
                }
            }

            Files.createDirectories(STORAGE.resolve("opened"));
            String safeName=Paths.get(name).getFileName().toString();
            Path temp=Files.createTempFile(
                    STORAGE.resolve("opened"),
                    "CryptoSafe_",
                    "_" + safeName
            );
            Path opened=decryptToFile(fileId,shared,temp);
            opened.toFile().deleteOnExit();

            if(!Desktop.isDesktopSupported())
                throw new Exception("Opening files is not supported on this computer.");

            Desktop.getDesktop().open(opened.toFile());
        }
    }

    // ===================== UI HELPERS ==========================
    static final String FONT_FAMILY = pickFont();
    static String pickFont() {
        Set<String> have = new HashSet<>(Arrays.asList(
                GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames()));
        for (String f : new String[]{"Segoe UI", "SF Pro Text", "Helvetica Neue", "Ubuntu", "Noto Sans", "DejaVu Sans"})
            if (have.contains(f)) return f;
        return Font.SANS_SERIF;
    }
    static Font font(int size, boolean bold) {
        return new Font(FONT_FAMILY, bold ? Font.BOLD : Font.PLAIN, size);
    }
    // ===================== THEME (edit these hex codes to re-colour the app) =====================
    // ACCENT = buttons/table headers, ACCENT_DARK = headings, ACCENT_LIGHT = selection/hover,
    // BG = page background, TEXT_DARK / TEXT_MUTED = text colours, BORDER = field borders.
    // Sidebar colours: SIDEBAR* in DashboardFrame. Login gradient: GradientPanel.
    static Color ACCENT = Color.decode("#3F5F8A");
    static Color ACCENT_DARK = Color.decode("#2B3A4F");
    static Color ACCENT_LIGHT = Color.decode("#E8EEF5");
    static Color BG = Color.decode("#F5F7FA");
    static Color TEXT_DARK = Color.decode("#2B3440");
    static Color TEXT_MUTED = Color.decode("#6B7785");
    static Color BORDER = Color.decode("#D5DCE4");
    static Color WHITE = Color.WHITE;
    static void installModernLook() {
        UIManager.put("OptionPane.background", WHITE);
        UIManager.put("Panel.background", WHITE);
        UIManager.put("OptionPane.messageForeground", TEXT_DARK);
        UIManager.put("Button.font", font(13, true));
        UIManager.put("Label.font", font(13, false));

        // Dark text defaults
        UIManager.put("Label.foreground", TEXT_DARK);
        UIManager.put("TextField.foreground", TEXT_DARK);
        UIManager.put("PasswordField.foreground", TEXT_DARK);
        UIManager.put("ComboBox.foreground", TEXT_DARK);
        UIManager.put("ComboBox.background", WHITE);
        UIManager.put("Table.foreground", TEXT_DARK);
        UIManager.put("Table.selectionForeground", TEXT_DARK);
        UIManager.put("Button.foreground", TEXT_DARK);   // only plain JButtons (dialogs, file chooser)
    }
    static class RoundedPanel extends JPanel {
        private final int radius;
        RoundedPanel(int radius, Color bg) {
            super();
            this.radius = radius;
            setOpaque(false);
            setBackground(bg);
        }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(getBackground());
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), radius, radius);
            g2.dispose();
            super.paintComponent(g);
        }
    }
    static class GradientPanel extends JPanel {
        GradientPanel() { setOpaque(false); }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            GradientPaint gp = new GradientPaint(
                    0, 0, Color.decode("#E8EEF5"),
                    getWidth(), getHeight(), Color.decode("#BFCCDD"));
            g2.setPaint(gp);
            g2.fillRect(0, 0, getWidth(), getHeight());
            // Soft abstract waves similar to the reference design.
            g2.setColor(new Color(255, 255, 255, 90));
            g2.fillOval(-140, -100, 500, 330);
            g2.fillOval(180, 300, 520, 330);
            g2.setColor(new Color(255, 255, 255, 60));
            g2.fillOval(-90, 430, 470, 260);
            g2.dispose();
            super.paintComponent(g);
        }
    }
    static class RoundedButton extends JButton {
        private final Color normal;
        private final Color hover;
        RoundedButton(String text, Color color) {
            super(text);
            normal = color;
            hover = color.brighter();
            setFont(font(14, true));
            setForeground(Color.WHITE);
            setBackground(normal);
            setFocusPainted(false);
            setBorderPainted(false);
            setContentAreaFilled(false);
            setOpaque(false);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setBorder(new EmptyBorder(13, 22, 13, 22));
            addMouseListener(new java.awt.event.MouseAdapter() {
                public void mouseEntered(java.awt.event.MouseEvent e) { setBackground(hover); repaint(); }
                public void mouseExited(java.awt.event.MouseEvent e) { setBackground(normal); repaint(); }
            });
        }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(getBackground());
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), 22, 22);
            g2.dispose();
            super.paintComponent(g);
        }
    }
    static class OutlineButton extends JButton {
        OutlineButton(String text) {
            super(text);
            setFont(font(14, true));
            setForeground(ACCENT_DARK);
            setBackground(new Color(245, 247, 250));
            setFocusPainted(false);
            setContentAreaFilled(false);
            setOpaque(false);
            setBorder(new EmptyBorder(12, 20, 12, 20));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(getModel().isRollover() ? ACCENT_LIGHT : getBackground());
            g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 22, 22);
            g2.setColor(Color.decode("#BCC8D6"));
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 22, 22);
            g2.dispose();
            super.paintComponent(g);
        }
    }
    static class ModernTextField extends JTextField {
        private final String hint;
        ModernTextField(String hint) {
            this.hint = hint;
            setFont(font(14, false));
            setForeground(TEXT_DARK);
            setBackground(Color.WHITE);
            setOpaque(false);
            setBorder(new EmptyBorder(12, 16, 12, 16));
        }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(Color.WHITE);
            g2.fillRoundRect(0, 0, getWidth()-1, getHeight()-1, 12, 12);
            g2.setColor(hasFocus() ? ACCENT : BORDER);
            g2.drawRoundRect(0, 0, getWidth()-1, getHeight()-1, 12, 12);
            if (getText().isEmpty() && !hasFocus()) {
                g2.setFont(font(14, false));
                g2.setColor(TEXT_MUTED);
                g2.drawString(hint, 16, getHeight()/2 + 5);
            }
            g2.dispose();
            super.paintComponent(g);
        }
    }
    static class ModernPasswordField extends JPasswordField {
        private final String hint;
        ModernPasswordField(String hint) {
            this.hint = hint;
            setFont(font(14, false));
            setForeground(TEXT_DARK);
            setBackground(Color.WHITE);
            setOpaque(false);
            setBorder(new EmptyBorder(12, 16, 12, 16));
        }
        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(Color.WHITE);
            g2.fillRoundRect(0, 0, getWidth()-1, getHeight()-1, 12, 12);
            g2.setColor(hasFocus() ? ACCENT : BORDER);
            g2.drawRoundRect(0, 0, getWidth()-1, getHeight()-1, 12, 12);
            if (getPassword().length == 0 && !hasFocus()) {
                g2.setFont(font(14, false));
                g2.setColor(TEXT_MUTED);
                g2.drawString(hint, 16, getHeight()/2 + 5);
            }
            g2.dispose();
            super.paintComponent(g);
        }
    }
    static JButton button(String text) {
        return new RoundedButton(text, ACCENT);
    }
    static JLabel title(String text) {
        JLabel l = new JLabel(text);
        l.setFont(font(25, true));
        l.setForeground(ACCENT_DARK);
        return l;
    }
    static JTextField field(int columns) {
        return new JTextField(columns);
    }
    static JPasswordField pass(int columns) {
        return new JPasswordField(columns);
    }
    static void styleTable(JTable t) {
        t.setFont(font(12, false));
        t.setRowHeight(34);
        t.setShowGrid(false);
        t.setFillsViewportHeight(true);
        t.setIntercellSpacing(new Dimension(0, 1));
        t.setBackground(Color.WHITE);
        t.setForeground(TEXT_DARK);
        t.setSelectionBackground(ACCENT_LIGHT);
        t.setSelectionForeground(TEXT_DARK);
        t.getTableHeader().setFont(font(12, true));
        t.getTableHeader().setReorderingAllowed(false);
        if (t.getColumnCount() > 0) t.getColumnModel().getColumn(0).setMaxWidth(70);
        t.getTableHeader().setPreferredSize(new Dimension(0, 36));

        // Custom header renderer: the system look and feel ignores setBackground/setForeground
        // on the header, so we draw it ourselves. Change the two colours below to restyle it.
        final Color HEADER_BG = ACCENT_LIGHT;   // header background
        final Color HEADER_FG = ACCENT_DARK;    // header text colour
        javax.swing.table.DefaultTableCellRenderer headerRenderer = new javax.swing.table.DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                super.getTableCellRendererComponent(table, value, false, false, row, column);
                setBackground(HEADER_BG);
                setForeground(HEADER_FG);
                setFont(font(12, true));
                setOpaque(true);
                setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(0, 0, 2, 0, ACCENT),
                        new EmptyBorder(0, 10, 0, 10)));
                return this;
            }
        };
        for (int i = 0; i < t.getColumnModel().getColumnCount(); i++)
            t.getColumnModel().getColumn(i).setHeaderRenderer(headerRenderer);
    }
    static boolean confirm(String msg) {
        return JOptionPane.showConfirmDialog(null, msg, "CryptoSafe",
                JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION;
    }
    static String friendlyMessage(Exception e) {
        String m = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
        if (m.contains("unauthorized file access"))
            return "You do not have access to this file.";
        if (m.contains("integrity verification failed"))
            return "Integrity check failed: the stored file was modified or corrupted. Nothing was decrypted.";
        if (e instanceof AEADBadTagException || m.contains("tag mismatch"))
            return "Decryption failed: the encrypted file was modified or the key does not match.";
        if (e instanceof NoSuchFileException)
            return "The encrypted file could not be found on disk.";
        if (m.contains("duplicate") || m.contains("unique constraint"))
            return "That username or email is already registered.";
        if (e instanceof SQLException)
            return "Database error: " + e.getMessage();
        return e.getMessage() == null ? "Something went wrong. Please try again." : e.getMessage();
    }
    static void error(Exception e) {
        JOptionPane.showMessageDialog(null, friendlyMessage(e),
                "CryptoSafe", JOptionPane.ERROR_MESSAGE);
    }
    static void success(Component parent, String message) {
        JOptionPane.showMessageDialog(parent, message,
                "CryptoSafe", JOptionPane.INFORMATION_MESSAGE);
    }
    static JLabel sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(font(13, true));
        l.setForeground(TEXT_DARK);
        return l;
    }
    static JPanel card() {
        RoundedPanel p = new RoundedPanel(22, Color.WHITE);
        p.setBorder(new EmptyBorder(26, 30, 26, 30));
        return p;
    }
    static JPanel brandPanel() {
        GradientPanel left = new GradientPanel();
        left.setLayout(new BorderLayout());
        left.setBorder(new EmptyBorder(60, 55, 50, 55));
        JPanel text = new JPanel();
        text.setOpaque(false);
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        JLabel logo = new JLabel("CryptoSafe");
        logo.setFont(font(44, true));
        logo.setForeground(ACCENT_DARK);
        logo.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel line1 = whiteLabel("Your files.", 24, false);
        JLabel line2 = whiteLabel("Your keys.", 24, false);
        JLabel line3 = whiteLabel("Your rules.", 24, false);
        JSeparator sep = new JSeparator();
        sep.setForeground(new Color(43, 58, 79, 150));
        sep.setMaximumSize(new Dimension(270, 1));
        JLabel tech = whiteLabel("AES-256  •  RSA-3072", 16, false);
        JLabel tech2 = whiteLabel("SHA-256  •  Access Control", 16, false);
        JLabel tagline = whiteLabel(
                "<html><div style='text-align:center'>Encrypted storage, verified integrity,<br>and keys that only you control.</div></html>",
                15, false);
        tagline.setHorizontalAlignment(SwingConstants.CENTER);
        text.add(logo);
        text.add(Box.createVerticalStrut(28));
        text.add(line1);
        text.add(line2);
        text.add(line3);
        text.add(Box.createVerticalStrut(26));
        text.add(sep);
        text.add(Box.createVerticalStrut(22));
        text.add(tech);
        text.add(Box.createVerticalStrut(8));
        text.add(tech2);
        text.add(Box.createVerticalStrut(45));
        text.add(tagline);
        left.add(text, BorderLayout.NORTH);
        JPanel art = new JPanel() {
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2=(Graphics2D)g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int cx=getWidth()/2, cy=getHeight()/2;
                g2.setColor(new Color(43,58,79,40));
                g2.fillOval(cx-90, cy-90, 180, 180);
                g2.setColor(new Color(43,58,79,170));
                g2.setStroke(new BasicStroke(9));
                g2.drawRoundRect(cx-58, cy-42, 116, 120, 25, 25);
                g2.drawArc(cx-38, cy-85, 76, 80, 0, 180);
                g2.setColor(new Color(43,58,79,200));
                g2.fillRoundRect(cx-14, cy+2, 28, 42, 12, 12);
                g2.fillOval(cx-7, cy+15, 14, 14);
                g2.dispose();
            }
        };
        art.setOpaque(false);
        left.add(art, BorderLayout.CENTER);
        return left;
    }
    static JLabel whiteLabel(String text, int size, boolean bold) {
        JLabel l = new JLabel(text);
        l.setFont(font(size, bold));
        l.setForeground(ACCENT_DARK);
        return l;
    }
    static JPanel formPanel(String heading, String subtitle) {
        JPanel p = new JPanel();
        p.setBackground(Color.WHITE);
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(new EmptyBorder(58, 62, 45, 62));
        JLabel h = new JLabel(heading);
        h.setFont(font(38, true));
        h.setForeground(ACCENT_DARK);
        h.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel s = new JLabel(subtitle);
        s.setFont(font(16, false));
        s.setForeground(TEXT_DARK);
        s.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.add(h);
        p.add(Box.createVerticalStrut(10));
        p.add(s);
        return p;
    }
    static JPanel labelField(String label, JComponent field) {
        JPanel p = new JPanel(new BorderLayout(0, 8));
        p.setOpaque(false);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        field.setPreferredSize(new Dimension(100, 46));
        p.add(sectionLabel(label), BorderLayout.NORTH);
        p.add(field, BorderLayout.CENTER);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, p.getPreferredSize().height));
        return p;
    }
    static void configureFrame(JFrame f, int w, int h) {
        f.setSize(w, h);
        f.setLocationRelativeTo(null);
        f.setResizable(false);
        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
    // ===================== LOGIN ================================
    static class LoginFrame extends JFrame {
        ModernTextField user = new ModernTextField("Enter your username");
        ModernPasswordField password = new ModernPasswordField("Enter your password");
        LoginFrame() {
            super("CryptoSafe — Secure Login");
            configureFrame(this, 1120, 700);
            JPanel root = new JPanel(new BorderLayout());
            root.setBackground(BG);
            JPanel left = brandPanel();
            left.setPreferredSize(new Dimension(480, 700));
            JPanel right = new JPanel(new BorderLayout());
            right.setBackground(Color.WHITE);
            JPanel form = formPanel("Welcome Back", "Your secure workspace is waiting.");
            form.add(Box.createVerticalStrut(42));
            form.add(labelField("Username", user));
            form.add(Box.createVerticalStrut(20));
            form.add(labelField("Password", password));
            form.add(Box.createVerticalStrut(10));
            JLabel security = new JLabel("AES-256-GCM  •  RSA-OAEP  •  SHA-256");
            security.setFont(font(12, false));
            security.setForeground(TEXT_MUTED);
            security.setAlignmentX(Component.LEFT_ALIGNMENT);
            form.add(security);
            form.add(Box.createVerticalStrut(24));
            RoundedButton login = new RoundedButton("Log In", ACCENT);
            login.setAlignmentX(Component.LEFT_ALIGNMENT);
            login.setMaximumSize(new Dimension(Integer.MAX_VALUE, 50));
            OutlineButton register = new OutlineButton("Create Account");
            register.setAlignmentX(Component.LEFT_ALIGNMENT);
            register.setMaximumSize(new Dimension(Integer.MAX_VALUE, 48));
            form.add(login);
            form.add(Box.createVerticalStrut(14));
            form.add(register);
            right.add(form, BorderLayout.CENTER);
            root.add(left, BorderLayout.WEST);
            root.add(right, BorderLayout.CENTER);
            add(root);
            login.addActionListener(e -> doLogin());
            register.addActionListener(e -> {
                dispose();
                new RegisterFrame().setVisible(true);
            });
            getRootPane().setDefaultButton(login);
        }
        void doLogin() {
            String username = user.getText().trim();
            char[] pw = password.getPassword();
            try {
                if (username.isEmpty()) throw new Exception("Please enter a username.");
                if (pw.length == 0) throw new Exception("Please enter your password.");
                session = Auth.login(username, pw);
                Arrays.fill(pw, '\0');
                dispose();
                new DashboardFrame().setVisible(true);
            } catch (Exception e) {
                Arrays.fill(pw, '\0');
                error(e);
            }
        }
    }
    // ===================== REGISTER =============================
    static class RegisterFrame extends JFrame {
        ModernTextField user = new ModernTextField("Choose a unique username");
        ModernTextField email = new ModernTextField("Enter your email");
        ModernPasswordField p1 = new ModernPasswordField("Create a strong password");
        ModernPasswordField p2 = new ModernPasswordField("Re-enter your password");
        RoundedButton create;
        RegisterFrame() {
            super("CryptoSafe — Create Account");
            configureFrame(this, 1120, 760);
            JPanel root = new JPanel(new BorderLayout());
            root.setBackground(BG);
            JPanel left = brandPanel();
            left.setPreferredSize(new Dimension(480, 760));
            JPanel right = new JPanel(new BorderLayout());
            right.setBackground(Color.WHITE);
            JPanel form = formPanel("Create Account", "Let's get your secure workspace ready.");
            form.add(Box.createVerticalStrut(32));
            form.add(labelField("Username", user));
            form.add(Box.createVerticalStrut(16));
            form.add(labelField("Email", email));
            form.add(Box.createVerticalStrut(16));
            form.add(labelField("Password", p1));
            JLabel hint = new JLabel("Use at least 8 characters; longer is stronger.");
            hint.setFont(font(12, false));
            hint.setForeground(TEXT_MUTED);
            hint.setAlignmentX(Component.LEFT_ALIGNMENT);
            form.add(Box.createVerticalStrut(6));
            form.add(hint);
            form.add(Box.createVerticalStrut(16));
            form.add(labelField("Confirm Password", p2));
            form.add(Box.createVerticalStrut(22));
            create = new RoundedButton("Create Account", ACCENT);
            create.setAlignmentX(Component.LEFT_ALIGNMENT);
            create.setMaximumSize(new Dimension(Integer.MAX_VALUE, 50));
            OutlineButton back = new OutlineButton("←  Back to Login");
            back.setAlignmentX(Component.LEFT_ALIGNMENT);
            back.setMaximumSize(new Dimension(Integer.MAX_VALUE, 48));
            form.add(create);
            form.add(Box.createVerticalStrut(12));
            form.add(back);
            right.add(form, BorderLayout.CENTER);
            root.add(left, BorderLayout.WEST);
            root.add(right, BorderLayout.CENTER);
            add(root);
            create.addActionListener(e -> register());
            back.addActionListener(e -> {
                dispose();
                new LoginFrame().setVisible(true);
            });
            getRootPane().setDefaultButton(create);
        }
        void register() {
            char[] a = p1.getPassword();
            char[] b = p2.getPassword();
            String un = user.getText().trim(), em = email.getText().trim();
            try {
                if (un.isEmpty()) throw new Exception("Please enter a username.");
                if (a.length == 0) throw new Exception("Please enter a password.");
                if (!Arrays.equals(a, b)) throw new Exception("Passwords do not match.");
            } catch (Exception e) {
                Arrays.fill(a, '\0'); Arrays.fill(b, '\0');
                error(e);
                return;
            }
            RegisterFrame self = this;
            setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            create.setEnabled(false);
            create.setText("Generating keys...");
            new SwingWorker<Void, Void>() {
                protected Void doInBackground() throws Exception { Auth.register(un, em, a); return null; }
                protected void done() {
                    Arrays.fill(a, '\0'); Arrays.fill(b, '\0');
                    setCursor(Cursor.getDefaultCursor());
                    try {
                        get();
                        success(self, "Account created. You can log in now.");
                        dispose();
                        new LoginFrame().setVisible(true);
                    } catch (Exception ex) {
                        create.setEnabled(true);
                        create.setText("Create Account");
                        Throwable t = ex.getCause() != null ? ex.getCause() : ex;
                        error(t instanceof Exception ? (Exception) t : new Exception(t));
                    }
                }
            }.execute();
        }
    }
    // ===================== DASHBOARD ===========================
    static class DashboardFrame extends JFrame {
    JPanel content = new JPanel(new BorderLayout());
    JLabel status = new JLabel("Welcome, " + session.username);
    static final Color SIDEBAR          = Color.decode("#E8EEF5");
    static final Color SIDEBAR_DARK     = Color.decode("#D5DFEB");
    static final Color SIDEBAR_SELECTED = Color.WHITE;
    static final Color SIDEBAR_TEXT     = Color.decode("#2B3A4F");
    Map<String, NavButton> navButtons = new LinkedHashMap<>();
    DashboardFrame() {
        super("CryptoSafe — Secure Vault");
        setSize(1240, 760);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BG);
        // =========================================================
        // SIDEBAR
        // =========================================================
        JPanel side = new JPanel(new BorderLayout());
        side.setBackground(SIDEBAR);
        side.setPreferredSize(new Dimension(250, 760));
        side.setBorder(new EmptyBorder(28, 16, 22, 16));
        JLabel logo = new JLabel("CryptoSafe");
        logo.setFont(font(28, true));
        logo.setForeground(ACCENT_DARK);
        logo.setBorder(new EmptyBorder(0, 8, 28, 0));
        side.add(logo, BorderLayout.NORTH);
        JPanel nav = new JPanel();
        nav.setOpaque(false);
        nav.setLayout(new BoxLayout(nav, BoxLayout.Y_AXIS));
        addNavButton(nav, "Dashboard", "⌂");
        addNavButton(nav, "My Files", "▣");
        addNavButton(nav, "Shared With Me", "↗");
        addNavButton(nav, "Upload File", "↑");
        addNavButton(nav, "Share / Revoke", "⇄");
        addNavButton(nav, "Key Management", "◆");
        addNavButton(nav, "Profile", "♙");
        side.add(nav, BorderLayout.CENTER);
        JLabel secure = new JLabel(
                "<html><center>" +
                "● SECURE SESSION<br>" +
                "RSA-3072 • AES-256" +
                "</center></html>"
        );
        secure.setHorizontalAlignment(SwingConstants.CENTER);
        secure.setFont(font(11, true));
        secure.setForeground(TEXT_MUTED);
        side.add(secure, BorderLayout.SOUTH);
        // =========================================================
        // MAIN AREA
        // =========================================================
        JPanel main = new JPanel(new BorderLayout());
        main.setBackground(BG);
        JPanel top = new JPanel(new BorderLayout());
        top.setBackground(Color.WHITE);
        top.setBorder(new EmptyBorder(18, 28, 18, 28));
        JPanel topLeft = new JPanel();
        topLeft.setOpaque(false);
        topLeft.setLayout(new BoxLayout(topLeft, BoxLayout.Y_AXIS));
        JLabel heading = new JLabel("Secure File Vault");
        heading.setFont(font(25, true));
        heading.setForeground(ACCENT_DARK);
        status.setFont(font(13, false));
        status.setForeground(TEXT_MUTED);
        topLeft.add(heading);
        topLeft.add(Box.createVerticalStrut(4));
        topLeft.add(status);
        RoundedButton logout = new RoundedButton("Logout", ACCENT);
        logout.addActionListener(e -> logout());
        top.add(topLeft, BorderLayout.WEST);
        top.add(logout, BorderLayout.EAST);
        content.setBackground(BG);
        content.setBorder(new EmptyBorder(24, 28, 24, 28));
        main.add(top, BorderLayout.NORTH);
        main.add(content, BorderLayout.CENTER);
        root.add(side, BorderLayout.WEST);
        root.add(main, BorderLayout.CENTER);
        add(root);
        navigate("Dashboard");
    }
    // =============================================================
    // SIDEBAR BUTTON
    // =============================================================
    void addNavButton(
            JPanel nav,
            String page,
            String icon
    ) {
        NavButton b = new NavButton(icon + "   " + page);
        navButtons.put(page, b);
        b.addActionListener(e -> navigate(page));
        nav.add(b);
        nav.add(Box.createVerticalStrut(8));
    }
    // =============================================================
    // NAVIGATION
    // =============================================================
    void navigate(String page) {
        // Highlight selected button
        for (Map.Entry<String, NavButton> entry : navButtons.entrySet()) {
            entry.getValue().setSelectedState(
                    entry.getKey().equals(page)
            );
        }
        content.removeAll();
        try {
            switch (page) {
                case "Dashboard":
                    content.add(home(), BorderLayout.CENTER);
                    break;
                case "My Files":
                    content.add(myFilesPanel(), BorderLayout.CENTER);
                    break;
                case "Shared With Me":
                    content.add(sharedPanel(), BorderLayout.CENTER);
                    break;
                case "Upload File":
                    upload();
                    return;
                case "Share / Revoke":
                    content.add(sharePanel(), BorderLayout.CENTER);
                    break;
                case "Key Management":
                    content.add(keyPanel(), BorderLayout.CENTER);
                    break;
                case "Profile":
                    content.add(profilePanel(), BorderLayout.CENTER);
                    break;
                default:
                    content.add(home(), BorderLayout.CENTER);
            }
        } catch (Exception e) {
            error(e);
            content.add(home(), BorderLayout.CENTER);
        }
        content.revalidate();
        content.repaint();
    }
    // =============================================================
    // LOGOUT
    // =============================================================
    void logout() {

        session = null;
        dispose();
        new LoginFrame().setVisible(true);
    }
    // =============================================================
    // DASHBOARD HOME
    // =============================================================
    JPanel home() {
        JPanel p = new JPanel(new BorderLayout(18, 18));
        p.setBackground(BG);
        RoundedPanel welcome = new RoundedPanel(22, Color.WHITE);
        welcome.setLayout(new BorderLayout());
        welcome.setBorder(
                new EmptyBorder(28, 32, 28, 32)
        );
        JLabel h = new JLabel(
                "Welcome back, " + session.username
        );
        h.setFont(font(27, true));
        h.setForeground(ACCENT_DARK);
        JLabel info = new JLabel(
                "<html>" +
                "Your files stay encrypted, your keys stay protected,<br>" +
                "and access is granted only to the people you choose." +
                "</html>"
        );
        info.setFont(font(14, false));
        info.setForeground(TEXT_DARK);
        welcome.add(h, BorderLayout.NORTH);
        welcome.add(info, BorderLayout.CENTER);
        int mine = 0, sharedCount = 0;
        try { mine = FileService.myFiles().size(); sharedCount = FileService.sharedFiles().size(); } catch (Exception ignored) {}
        JPanel cards = new JPanel(new GridLayout(1, 3, 16, 0));
        cards.setOpaque(false);
        cards.setPreferredSize(new Dimension(0, 130));
        cards.add(statCard(String.valueOf(mine), "Files you have encrypted"));
        cards.add(statCard(String.valueOf(sharedCount), "Files shared with you"));
        cards.add(statCard("Protected", "AES-256 + RSA-3072 active"));
        JPanel mid = new JPanel(new BorderLayout());
        mid.setOpaque(false);
        mid.setLayout(new BorderLayout(0, 18));
        mid.add(cards, BorderLayout.NORTH);
        RoundedPanel lower = new RoundedPanel(
                22,
                Color.WHITE
        );
        lower.setLayout(new BorderLayout());
        lower.setBorder(
                new EmptyBorder(24, 28, 24, 28)
        );
        JLabel sec = new JLabel(
                "Your security stack"
        );
        sec.setFont(font(18, true));
        sec.setForeground(TEXT_DARK);
        JLabel details = new JLabel(
                "<html>" +
                "✓ AES-256-GCM encrypts your files<br>" +
                "✓ RSA-OAEP with SHA-256 protects file keys<br>" +
                "✓ PBKDF2 protects account passwords<br>" +
                "✓ Access control checks sharing and revocation<br>" +
                "✓ SHA-256 verifies recovered file integrity" +
                "</html>"
        );
        details.setFont(font(13, false));
        details.setForeground(TEXT_MUTED);
        lower.add(sec, BorderLayout.NORTH);
        lower.add(details, BorderLayout.CENTER);
        p.add(welcome, BorderLayout.NORTH);
        JPanel lowerWrap = new JPanel(new BorderLayout());
        lowerWrap.setOpaque(false);
        lowerWrap.add(lower, BorderLayout.NORTH);
        mid.add(lowerWrap, BorderLayout.CENTER);
        p.add(mid, BorderLayout.CENTER);
        return p;
    }
    JPanel statCard(String big, String small) {
        RoundedPanel c = new RoundedPanel(
                18,
                Color.WHITE
        );
        c.setLayout(
                new BoxLayout(c, BoxLayout.Y_AXIS)
        );
        c.setBorder(
                new EmptyBorder(22, 24, 22, 24)
        );
        JLabel b = new JLabel(big);
        b.setFont(font(22, true));
        b.setForeground(ACCENT_DARK);
        JLabel s = new JLabel(small);
        s.setFont(font(12, false));
        s.setForeground(TEXT_MUTED);
        c.add(b);
        c.add(Box.createVerticalStrut(6));
        c.add(s);
        return c;
    }
    // =============================================================
    // MY FILES
    // =============================================================
    JPanel myFilesPanel() throws Exception {
        JPanel p = new JPanel(
                new BorderLayout(12, 12)
        );
        p.setBackground(BG);
        JLabel h = title("My Files");
        p.add(h, BorderLayout.NORTH);
        String[] cols = {
                "ID",
                "File",
                "Size (bytes)",
                "SHA-256",
                "Created"
        };
        DefaultTableModelCompat model =
                new DefaultTableModelCompat(cols);
        for (Object[] x : FileService.myFiles()) {
            model.addRow(x);
        }
        JTable table = new JTable(model);
        styleTable(table);
        JScrollPane scroll =
                new JScrollPane(table);
        scroll.setBorder(
                BorderFactory.createLineBorder(
                        BORDER
                )
        );
        p.add(scroll, BorderLayout.CENTER);
        JPanel actions = new JPanel(
                new FlowLayout(
                        FlowLayout.LEFT,
                        10,
                        5
                )
        );
        actions.setOpaque(false);
        RoundedButton open =
                new RoundedButton(
                        "Open",
                        ACCENT
                );
        RoundedButton download =
                new RoundedButton(
                        "Decrypt / Download",
                        ACCENT
                );
        OutlineButton refresh =
                new OutlineButton("Refresh");
        actions.add(open);
        actions.add(download);
        actions.add(refresh);
        p.add(actions, BorderLayout.SOUTH);
        open.addActionListener(
                e -> openSelected(table, false)
        );
        download.addActionListener(
                e -> downloadSelected(table, false)
        );
        refresh.addActionListener(
                e -> navigate("My Files")
        );
        return p;
    }
    // =============================================================
    // SHARED WITH ME
    // =============================================================
    JPanel sharedPanel() throws Exception {
        JPanel p = new JPanel(
                new BorderLayout(12, 12)
        );
        p.setBackground(BG);
        p.add(
                title("Shared With Me"),
                BorderLayout.NORTH
        );
        String[] cols = {
                "ID",
                "File",
                "Owner",
                "Status",
                "Shared At"
        };
        DefaultTableModelCompat model =
                new DefaultTableModelCompat(cols);
        for (Object[] x : FileService.sharedFiles()) {
            model.addRow(x);
        }
        JTable table = new JTable(model);
        styleTable(table);
        JScrollPane scroll =
                new JScrollPane(table);
        scroll.setBorder(
                BorderFactory.createLineBorder(
                        BORDER
                )
        );
        p.add(scroll, BorderLayout.CENTER);
        JPanel actions = new JPanel(
                new FlowLayout(
                        FlowLayout.LEFT,
                        10,
                        5
                )
        );
        actions.setOpaque(false);
        RoundedButton open =
                new RoundedButton(
                        "Open",
                        ACCENT
                );
        RoundedButton download =
                new RoundedButton(
                        "Decrypt / Download",
                        ACCENT
                );
        OutlineButton refresh =
                new OutlineButton("Refresh");
        actions.add(open);
        actions.add(download);
        actions.add(refresh);
        p.add(actions, BorderLayout.SOUTH);
        open.addActionListener(
                e -> openSelected(table, true)
        );
        download.addActionListener(
                e -> downloadSelected(table, true)
        );
        refresh.addActionListener(
                e -> navigate("Shared With Me")
        );
        return p;
    }
    // =============================================================
    // DOWNLOAD
    // =============================================================
    void downloadSelected(
            JTable table,
            boolean shared
    ) {
        int row =
                table.getSelectedRow();
        if (row < 0) {
            error(
                    new Exception(
                            "Select a file first."
                    )
            );
            return;
        }
        try {
            long fileId =
                    Long.parseLong(
                            table.getValueAt(
                                    row,
                                    0
                            ).toString()
                    );
            Path downloaded =
                    FileService.download(
                            fileId,
                            shared
                    );
            if (downloaded != null && Files.exists(downloaded)) {
                int choice = JOptionPane.showOptionDialog(
                        this,
                        "Your file has been decrypted and saved.",
                        "CryptoSafe",
                        JOptionPane.DEFAULT_OPTION,
                        JOptionPane.INFORMATION_MESSAGE,
                        null,
                        new Object[]{"Open File", "Close"},
                        "Open File"
                );
                if (choice == 0) {
                    Desktop.getDesktop().open(downloaded.toFile());
                }
            }
        } catch (Exception e) {
            error(e);
        }
    }

    // =============================================================
    // OPEN FILE
    // =============================================================
    void openSelected(
            JTable table,
            boolean shared
    ) {
        int row =
                table.getSelectedRow();
        if (row < 0) {
            error(
                    new Exception(
                            "Select a file first."
                    )
            );
            return;
        }
        try {
            long fileId =
                    Long.parseLong(
                            table.getValueAt(
                                    row,
                                    0
                            ).toString()
                    );
            FileService.open(
                    fileId,
                    shared
            );
        } catch (Exception e) {
            error(e);
        }
    }

    // =============================================================
    // UPLOAD
    // =============================================================
    void upload() {
        JFileChooser chooser =
                new JFileChooser();
        if (
                chooser.showOpenDialog(this)
                != JFileChooser.APPROVE_OPTION
        ) {
            navigate("Dashboard");
            return;
        }
        try {
            long id =
                    FileService.upload(
                            chooser
                                    .getSelectedFile()
                                    .toPath()
                    );
            success(
                    this,
                    "File encrypted and stored securely."
                    + "\nFile ID: "
                    + id
            );
            navigate("My Files");
        } catch (Exception e) {
            error(e);
            navigate("Dashboard");
        }
    }
    // =============================================================
    // SHARE / REVOKE
    // =============================================================
    JPanel sharePanel() {
        JPanel outer =
                new JPanel(
                        new GridBagLayout()
                );
        outer.setBackground(BG);
        RoundedPanel c =
                new RoundedPanel(
                        22,
                        Color.WHITE
                );
        c.setLayout(
                new GridBagLayout()
        );
        c.setBorder(
                new EmptyBorder(
                        30,
                        36,
                        30,
                        36
                )
        );
        add(
                c,
                0,
                0,
                title("Share / Revoke Access")
        );
        add(
                c,
                1,
                0,
                sectionLabel("File to share")
        );
        FilePicker id = new FilePicker();
        add(c, 2, 0, id);
        add(
                c,
                3,
                0,
                sectionLabel(
                        "Recipient Username"
                )
        );
        ModernTextField user =
                new ModernTextField(
                        "Enter recipient username"
                );
        add(c, 4, 0, user);
        RoundedButton share =
                new RoundedButton(
                        "Share File",
                        ACCENT
                );
        OutlineButton revoke =
                new OutlineButton(
                        "Revoke Access"
                );
        add(c, 5, 0, share);
        add(c, 6, 0, revoke);
        outer.add(c);
        share.addActionListener(e -> {
            try {
                if (id.getText().trim().isEmpty())
                    throw new Exception(
                            "Enter a file ID first."
                    );
                if (user.getText().trim().isEmpty())
                    throw new Exception(
                            "Please enter a username."
                    );
                long fileId =
                        Long.parseLong(
                                id.getText().trim()
                        );
                FileService.share(
                        fileId,
                        user.getText().trim()
                );
                success(
                        this,
                        "File shared securely."
                );
            } catch (NumberFormatException ex) {
                error(
                        new Exception(
                                "File ID must be a number."
                        )
                );
            } catch (Exception ex) {
                error(ex);
            }
        });
        revoke.addActionListener(e -> {
            try {
                if (
                        id.getText().trim().isEmpty()
                        ||
                        user.getText().trim().isEmpty()
                ) {
                    throw new Exception(
                            "Enter both a file ID and a username."
                    );
                }
                long fileId =
                        Long.parseLong(
                                id.getText().trim()
                        );
                FileService.revoke(
                        fileId,
                        user.getText().trim()
                );
                success(
                        this,
                        "Access revoked."
                );
            } catch (NumberFormatException ex) {
                error(
                        new Exception(
                                "File ID must be a number."
                        )
                );
            } catch (Exception ex) {
                error(ex);
            }
        });
        return outer;
    }
    // =============================================================
    // KEY MANAGEMENT
    // =============================================================
    String fingerprint() {
        try {
            String h = Crypto.sha256(Auth.getPublicKey(session.id).getEncoded());
            return h.substring(0, 32) + "<br>" + h.substring(32);
        } catch (Exception e) { return "unavailable"; }
    }
    JPanel keyPanel() {
        JPanel p =
                new JPanel(
                        new GridBagLayout()
                );
        p.setBackground(BG);
        RoundedPanel c =
                new RoundedPanel(
                        22,
                        Color.WHITE
                );
        c.setLayout(
                new BorderLayout(15, 15)
        );
        c.setBorder(
                new EmptyBorder(
                        32,
                        36,
                        32,
                        36
                )
        );
        JLabel h =
                title("Key Management");
        JLabel details =
                new JLabel(
                        "<html>" +
                        "<b>RSA-3072</b> key pair is generated during registration.<br><br>" +
                        "Your private key is encrypted before it is stored in the database.<br>" +
                        "AES file keys are wrapped using RSA-OAEP with SHA-256.<br><br>" +
                        "Private keys are never displayed in the GUI.<br><br>" +
                "<b>Public key fingerprint (SHA-256):</b><br>" + fingerprint() +
                        "</html>"
                );
        details.setFont(
                font(14, false)
        );
        details.setForeground(
                TEXT_DARK
        );
        c.add(h, BorderLayout.NORTH);
        c.add(details, BorderLayout.CENTER);
        p.add(c);
        return p;
    }
    // =============================================================
    // PROFILE
    // =============================================================
    JPanel profilePanel() {
        JPanel p =
                new JPanel(
                        new GridBagLayout()
                );
        p.setBackground(BG);
        RoundedPanel c =
                new RoundedPanel(
                        22,
                        Color.WHITE
                );
        c.setLayout(
                new BoxLayout(
                        c,
                        BoxLayout.Y_AXIS
                )
        );
        c.setBorder(
                new EmptyBorder(
                        32,
                        40,
                        32,
                        40
                )
        );
        c.add(title("Profile"));
        c.add(
                Box.createVerticalStrut(25)
        );
        c.add(
                profileRow(
                        "Username",
                        session.username
                )
        );
        c.add(
                profileRow(
                        "Email",
                        session.email
                )
        );
        c.add(
                profileRow(
                        "Session",
                        "Authenticated"
                )
        );
        p.add(c);
        return p;
    }
    JPanel profileRow(
            String key,
            String value
    ) {
        JPanel p =
                new JPanel(
                        new BorderLayout()
                );
        p.setOpaque(false);
        p.setBorder(
                new EmptyBorder(
                        8,
                        0,
                        8,
                        0
                )
        );
        JLabel k =
                new JLabel(key);
        k.setFont(
                font(13, true)
        );
        k.setForeground(
                TEXT_MUTED
        );
        JLabel v =
                new JLabel(value);
        v.setFont(
                font(14, false)
        );
        v.setForeground(
                TEXT_DARK
        );
        p.add(
                k,
                BorderLayout.WEST
        );
        p.add(
                v,
                BorderLayout.EAST
        );
        return p;
    }
    void add(
            JPanel p,
            int y,
            int x,
            Component comp
    ) {
        GridBagConstraints g =
                new GridBagConstraints();
        g.gridx = x;
        g.gridy = y;
        g.weightx = 1;
        g.insets =
                new Insets(
                        9,
                        9,
                        9,
                        9
                );
        g.fill =
                GridBagConstraints.HORIZONTAL;
        p.add(comp, g);
    }
    // =============================================================
    // CUSTOM SIDEBAR BUTTON
    // =============================================================
    static class NavButton extends JButton {
        boolean selected = false;
        NavButton(String text) {
            super(text);
            setFont(
                    font(13, true)
            );
            setForeground(TEXT_DARK);
            setBackground(
                    Color.decode("#E8EEF5")
            );
            setHorizontalAlignment(
                    SwingConstants.LEFT
            );
            setFocusPainted(false);
            setBorderPainted(false);
            setContentAreaFilled(false);
            setOpaque(false);
            setCursor(
                    Cursor.getPredefinedCursor(
                            Cursor.HAND_CURSOR
                    )
            );
            setBorder(
                    new EmptyBorder(
                            13,
                            16,
                            13,
                            16
                    )
            );
            setMaximumSize(
                    new Dimension(
                            Integer.MAX_VALUE,
                            48
                    )
            );
        }
        void setSelectedState(
                boolean value
        ) {
            selected = value;
            setForeground(selected ? ACCENT_DARK : TEXT_DARK);
            repaint();
        }
        @Override
        protected void paintComponent(
                Graphics g
        ) {
            Graphics2D g2 =
                    (Graphics2D) g.create();
            g2.setRenderingHint(
                    RenderingHints.KEY_ANTIALIASING,
                    RenderingHints.VALUE_ANTIALIAS_ON
            );
            if (selected) {
                g2.setColor(
                        SIDEBAR_SELECTED
                );
            } else if (getModel().isRollover()) {
                g2.setColor(
                        Color.decode("#D3DEEB")
                );
            } else {
                g2.setColor(
                        SIDEBAR
                );
            }
            g2.fillRoundRect(
                    0,
                    0,
                    getWidth(),
                    getHeight(),
                    12,
                    12
            );
            g2.dispose();
            super.paintComponent(g);
        }
    }
    }

    static class FilePicker extends JComboBox<String> {
        FilePicker() {
            setFont(font(14, false));
            setBackground(Color.WHITE);
            try { for (Object[] r : FileService.myFiles()) addItem(r[0] + " - " + r[1]); } catch (Exception ignored) {}
            if (getItemCount() == 0) addItem("(upload a file first)");
            setPreferredSize(new Dimension(100, 44));
        }
        String getText() {
            Object sel = getSelectedItem();
            if (sel == null) return "";
            String t = sel.toString();
            return t.matches("\\d+ - .*") ? t.substring(0, t.indexOf(' ')) : "";
        }
    }
    static class DefaultTableModelCompat extends javax.swing.table.DefaultTableModel {
        DefaultTableModelCompat(String[] cols) {
            super(cols, 0);
        }
        public boolean isCellEditable(int r, int c) {
            return false;
        }
    }
}