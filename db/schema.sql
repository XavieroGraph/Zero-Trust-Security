-- ==============================================================================
-- ZERO TRUST SECURITY - DATABASE SCHEMA
-- Mata Kuliah: Keamanan Informasi - Informatika Universitas Siliwangi
-- Sesuai Prinsip NIST SP 800-207
-- ==============================================================================

-- 1. Tabel Users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nama TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'dosen', 'mahasiswa')),
    nim TEXT UNIQUE,  -- Khusus Mahasiswa
    nidn TEXT UNIQUE, -- Khusus Dosen
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabel Devices (Verifikasi Konteks: X-Device-ID Terdaftar)
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    device_name TEXT,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, device_id)
);

-- 3. Tabel Refresh Tokens (Dapat dicabut / revoked saat logout)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    is_revoked INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 4. Tabel Kelas (Mata Kuliah yang diampu oleh Dosen tertentu)
CREATE TABLE IF NOT EXISTS kelas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kode_mk TEXT NOT NULL,
    nama_mk TEXT NOT NULL,
    sks INTEGER DEFAULT 3,
    dosen_id INTEGER NOT NULL REFERENCES users(id),
    is_final INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 5. Tabel Nilai (Data nilai mahasiswa di suatu kelas)
CREATE TABLE IF NOT EXISTS nilai (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kelas_id INTEGER NOT NULL REFERENCES kelas(id) ON DELETE CASCADE,
    mahasiswa_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nilai_angka REAL DEFAULT 0,
    nilai_huruf TEXT DEFAULT 'E',
    is_final INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(kelas_id, mahasiswa_id)
);

-- 6. Tabel Transkrip (Data transkrip resmi mahasiswa)
CREATE TABLE IF NOT EXISTS transkrip (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mahasiswa_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nim TEXT NOT NULL,
    kode_mk TEXT NOT NULL,
    nama_mk TEXT NOT NULL,
    sks INTEGER NOT NULL,
    nilai_huruf TEXT NOT NULL,
    synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(nim, kode_mk)
);

-- 7. Tabel Audit Logs (NIST SP 800-207: Continuous Monitoring & Telemetry)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    subject TEXT NOT NULL,       -- username/NIM/service ID
    endpoint TEXT NOT NULL,      -- request URL path
    method TEXT NOT NULL,        -- GET, POST, PUT, DELETE
    device_id TEXT,              -- X-Device-ID header
    decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'DENY')),
    reason TEXT NOT NULL         -- Alasan keputusan Policy Engine
);

-- Indexes untuk optimasi query Policy Engine
CREATE INDEX IF NOT EXISTS idx_devices_lookup ON devices(user_id, device_id);
CREATE INDEX IF NOT EXISTS idx_refresh_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_nilai_mahasiswa ON nilai(mahasiswa_id);
CREATE INDEX IF NOT EXISTS idx_kelas_dosen ON kelas(dosen_id);
CREATE INDEX IF NOT EXISTS idx_transkrip_nim ON transkrip(nim);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
