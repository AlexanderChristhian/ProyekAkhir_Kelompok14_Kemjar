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
// SECURE FILE UPLOAD IMPLEMENTATION
// ==========================================
const storage = multer.diskStorage({
    destination: uploadDir,
    filename: function (req, file, cb) {
        // [SECURE] Rename file to prevent overwriting and sanitize filename
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

// [SECURE] Add File Size Limit and File Filter
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // Limit: 50MB (Increased for video)
    fileFilter: (req, file, cb) => {
        // Allowed extensions
        const filetypes = /jpeg|jpg|png|pdf|docx|mp4/;
        // Check extension
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        // Check mime type
        const mimetype = filetypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Error: File upload only supports images, PDF, DOCX, and MP4!'));
        }
    }
}); 

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

// 1. Proses Upload (Secure)
app.post('/upload', (req, res) => {
    // [SECURE] Ensure user is logged in
    if (!req.session.user) {
        return res.redirect('/');
    }

    // [SECURE] Check Content-Length header before processing upload
    // This prevents the server from even accepting the stream if the declared size is too big
    const contentLength = parseInt(req.headers['content-length']);
    if (contentLength > 50 * 1024 * 1024) {
         return fs.readdir(uploadDir, (readErr, files) => {
            res.render('dashboard', {
                user: req.session.user,
                files: files || [],
                message: '<span class="text-danger">Error: File terlalu besar! Maksimal 50MB.</span>'
            });
        });
    }

    upload.single('file')(req, res, (err) => {
        if (err) {
            // [SECURE] Manual cleanup if file exists (Multer sometimes leaves partial files on error)
            if (req.file && req.file.path) {
                fs.unlink(req.file.path, (e) => { if(e) console.error("Cleanup error:", e); });
            }

            let errorMessage = err.message;
            if (err.code === 'LIMIT_FILE_SIZE') {
                errorMessage = 'Error: File terlalu besar! Maksimal 50MB.';
            }
            
            // Handle Multer Errors (File too large, wrong type)
            return fs.readdir(uploadDir, (readErr, files) => {
                res.render('dashboard', {
                    user: req.session.user,
                    files: files || [],
                    message: `<span class="text-danger">${errorMessage}</span>`
                });
            });
        }

        if (!req.file) {
            return res.send("Pilih file dulu!");
        }

        // File berhasil diupload dengan aman
        fs.readdir(uploadDir, (err, files) => {
            res.render('dashboard', {
                user: req.session.user,
                files: files || [],
                message: `File berhasil diupload! Tersimpan sebagai ${req.file.filename}`
            });
        });
    });
});

// 2. Proses Ganti Password (Secure)
app.post('/change-password', (req, res) => {
    // [SECURE] Get User ID from Session (Prevent IDOR)
    if (!req.session.user) {
        return res.redirect('/');
    }
    const userId = req.session.user.id;
    
    const { current_password, new_password } = req.body;

    // [SECURE] Verify Current Password First
    db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
        if (err || !user) {
            return res.status(500).send("Database Error");
        }

        if (user.password !== current_password) {
             return fs.readdir(uploadDir, (err, files) => {
                res.render('dashboard', {
                    user: req.session.user,
                    files: files || [],
                    message: '<span class="text-danger">Gagal! Password lama salah.</span>'
                });
            });
        }

        // Update password
        db.run("UPDATE users SET password = ? WHERE id = ?", [new_password, userId], function(err) {
            if (err) {
                return console.error(err.message);
            }
            
            // Update session data
            req.session.user.password = new_password;

            fs.readdir(uploadDir, (err, files) => {
                res.render('dashboard', {
                    user: req.session.user,
                    files: files || [],
                    message: 'Password Berhasil Diganti!'
                });
            });
        });
    });
});

app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});