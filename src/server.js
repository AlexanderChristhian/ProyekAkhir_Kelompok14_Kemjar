// server.js
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// 1. Setup Database SQLite (Memory / File)
const db = new sqlite3.Database(':memory:'); // Database tersimpan di RAM (hilang saat restart)

// Buat Tabel User & Isi Data Dummy
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
    // User 1: Admin (Korban)
    db.run("INSERT INTO users (username, password) VALUES ('admin', 'admin123')");
    // User 2: Karyawan (Akun yang kita pakai untuk menyerang)
    db.run("INSERT INTO users (username, password) VALUES ('karyawan', 'user123')");
    console.log("Database siap! User: admin/admin123 & karyawan/user123");
});

// 2. Setup Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Explicitly set views directory
app.use(express.static(path.join(__dirname, 'public'))); // Agar file upload bisa diakses publik
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'rahasia_negara',
    resave: false,
    saveUninitialized: true
}));

// Pastikan folder upload ada
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

// ==========================================
// VULNERABILITY 1: INSECURE FILE UPLOAD
// ==========================================
const storage = multer.diskStorage({
    destination: uploadDir,
    filename: function (req, file, cb) {
        // [VULNERABLE 1.1] Unrestricted File Extension
        // Kita menyimpan file dengan nama aslinya.
        // Jika user upload 'shell.html', tersimpan sebagai 'shell.html'.
        cb(null, file.originalname); 
    }
});

// [VULNERABLE 1.2] No File Size Limit
// Kita tidak menambahkan opsi 'limits: { fileSize: ... }'
// Kita juga tidak menambahkan 'fileFilter' untuk cek tipe file.
const upload = multer({ storage: storage }); 

// ==========================================
// ROUTES
// ==========================================

// Halaman Login
app.get('/', (req, res) => {
    res.render('login', { error: null }); // Pass error null to avoid reference error
});

// Proses Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, row) => {
        if (row) {
            req.session.loggedin = true;
            req.session.user = row; // Menyimpan data user di session
            res.redirect('/dashboard');
        } else {
            res.render('login', { error: 'Login Gagal! Username atau password salah.' });
        }
    });
});

// Halaman Dashboard
app.get('/dashboard', (req, res) => {
    if (req.session.loggedin) {
        // Read files for display
        fs.readdir(uploadDir, (err, files) => {
            const fileList = files || [];
            res.render('dashboard', { 
                user: req.session.user,
                files: fileList,
                message: null
            });
        });
    } else {
        res.redirect('/');
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// DEBUG ROUTE: Lihat isi database (Hanya untuk keperluan demo/testing)
app.get('/debug/users', (req, res) => {
    db.all("SELECT * FROM users", [], (err, rows) => {
        if (err) {
            res.status(500).send(err.message);
            return;
        }
        // Tampilkan dalam format JSON yang rapi
        res.send(`<pre>${JSON.stringify(rows, null, 2)}</pre><br><a href="/dashboard">Kembali ke Dashboard</a>`);
    });
});

// ==========================================
// ENDPOINT BERMASALAH (TARGET SERANGAN)
// ==========================================

// 1. Proses Upload (Vulnerable)
app.post('/upload', upload.single('file'), (req, res) => {
    if(!req.file) {
        return res.send("Pilih file dulu!");
    }
    // File berhasil diupload tanpa pengecekan
    // Re-render dashboard with success message
    fs.readdir(uploadDir, (err, files) => {
        res.render('dashboard', {
            user: req.session.user,
            files: files || [],
            message: `File berhasil diupload! Tersimpan di /uploads/${req.file.originalname}`
        });
    });
});

// 2. Proses Ganti Password (Vulnerable)
app.post('/change-password', (req, res) => {
    // [VULNERABLE 2.1] IDOR (Insecure Direct Object Reference)
    // Kita mengambil ID user dari 'req.body.user_id' (Input Hidden di Form)
    // BUKAN dari 'req.session.user.id' (Session Server).
    // Ini memungkinkan hacker mengubah ID orang lain.
    const targetUserId = req.body.user_id; 
    
    const newPassword = req.body.new_password;

    // [VULNERABLE 2.2] Missing Current Password Check
    // Kita langsung menjalankan perintah UPDATE tanpa validasi password lama.
    
    db.run("UPDATE users SET password = ? WHERE id = ?", [newPassword, targetUserId], function(err) {
        if (err) {
            return console.error(err.message);
        }
        
        fs.readdir(uploadDir, (err, files) => {
            res.render('dashboard', {
                user: req.session.user,
                files: files || [],
                message: `Password Berhasil Diganti untuk User ID: ${targetUserId}`
            });
        });
    });
});

app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});