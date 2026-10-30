# Tugas Praktikum Individu: Zero Trust Security (NIST SP 800-207)

**Mata Kuliah:** Keamanan Informasi (KP70065004)  
**Program Studi:** Informatika, Universitas Siliwangi  

---

## 1. Ringkasan & Prinsip Arsitektur

Proyek ini mengimplementasikan arsitektur keamanan modern **Zero Trust Architecture (ZTA)** sesuai standar **NIST SP 800-207** pada Sistem Informasi Nilai dan Transkrip Akademik.

### Prinsip Utama NIST SP 800-207 yang Diterapkan:
1. **Never Trust, Always Verify:**
   - Tidak ada perimeter jaringan internal yang dipercaya secara implisit.
   - Semua akses wajib melalui **API Gateway sebagai Policy Enforcement Point (PEP)**.
   - Resource microservice (Service Nilai & Service Transkrip) memverifikasi ulang token JWT dan `X-Gateway-Secret` secara mandiri.
2. **Least Privilege Access:**
   - Mahasiswa hanya dapat melihat nilai dan transkrip miliknya sendiri.
   - Dosen hanya dapat melihat, mengubah, dan memfinalisasi nilai pada kelas yang diampunya.
   - Admin hanya dapat melihat transkrip seluruh mahasiswa.
   - Endpoint sinkronisasi transkrip hanya menerima **Token Service (M2M)** dan menolak seluruh token pengguna.
3. **Continuous Context Verification:**
   - **Device Terdaftar:** Setiap request pengguna wajib menyertakan header `X-Device-ID` yang terdaftar di database untuk pengguna tersebut.
   - **Jam Akses:** Operasi pengubahan dan finalisasi nilai dibatasi hanya pada jam operasional (pukul 07.00 - 21.00 WIB) yang dapat dikonfigurasi melalui environment variables.
4. **Assume Breach & Telemetry Monitoring:**
   - Gateway mencatat seluruh evaluasi akses (ALLOW / DENY, subjek, endpoint, method, device ID, dan alasan keputusan) ke tabel `audit_logs` di database.
   - Komunikasi antar-service (Service Nilai ke Service Transkrip) tetap melewati Gateway menggunakan token service terdedikasi.

---

## 2. Struktur Direktori Proyek

```text
Praktikum Zero Trust Security/
│
├── config.js                       # Konfigurasi terpusat (port, secret, jam akses, service credentials)
├── package.json                    # Metadata proyek & daftar dependensi
├── README.md                       # Dokumentasi arsitektur, akun, panduan menjalankan, & curl
│
├── db/                             # Data Layer (SQLite)
│   ├── database.sqlite             # File database SQLite (terbentuk otomatis saat seed)
│   ├── db.js                       # Koneksi database & multi-version adapter (better-sqlite3 / node:sqlite)
│   ├── schema.sql                  # DDL skema tabel (users, devices, kelas, nilai, transkrip, audit_logs)
│   └── seed.js                     # Script inisialisasi & populasi data awal
│
├── gateway/                        # Policy Enforcement Point (PEP) & Policy Engine (PE/PA)
│   ├── gateway.js                  # API Gateway (Port 3000): auth endpoints, audit logging, proxying
│   └── policy.js                   # Modul Policy Engine (PE/PA): evaluasi kebijakan akses & konteks
│
├── services/                       # Resource Services (Microservices)
│   ├── nilai-service/              # Service Nilai (Port 3001)
│   │   ├── server.js               # Handler GET /nilai, PUT /nilai/:id, POST /kelas/:id/finalisasi
│   │   └── middleware/
│   │       └── verifyTrust.js      # Verifikasi ulang X-Gateway-Secret & JWT
│   │
│   └── transkrip-service/          # Service Transkrip (Port 3002)
│       ├── server.js               # Handler GET /transkrip/:nim, POST /transkrip/sinkron
│       └── middleware/
│           └── verifyTrust.js      # Verifikasi ulang X-Gateway-Secret & JWT
│
└── tests/                          # Automated Testing Suite
    ├── test-scenarios.js           # Skenario pengujian lengkap seluruh prinsip Zero Trust
    └── test-runner.js              # Runner pengujian otomatis end-to-end
```

---

## 3. Data Awal (Akun & Device Terdaftar)

Database telah disiapkan dengan data awal sesuai spesifikasi praktikum:

| Username | Password | Nama Lengkap | Role | NIM / NIDN | Device ID Terdaftar (`X-Device-ID`) | Keterangan Device |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `admin1` | `admin123` | Budi Santoso, M.Kom. | `admin` | - | `DEV-ADM-001` | Workstation Admin Biro TI |
| `dosen1` | `dosen123` | Dr. Husni Mubarok, M.T. | `dosen` | 0412058001 | `DEV-DSN-001` | MacBook Pro Dosen 1 |
| `dosen2` | `dosen123` | Alam Rahmatulloh, M.T. | `dosen` | 0418088502 | `DEV-DSN-002` | ThinkPad T14 Dosen 2 |
| `mhs1` | `mhs123` | Ahmad Fauzi | `mahasiswa` | 217006001 | `DEV-MHS-001` | Laptop Asus Mahasiswa 1 |
| `mhs2` | `mhs123` | Siti Nurhaliza | `mahasiswa` | 217006002 | `DEV-MHS-002` | Laptop Lenovo Mahasiswa 2 |
| `mhs3` | `mhs123` | Rian Hidayat | `mahasiswa` | 217006003 | `DEV-MHS-003` | Laptop Dell Mahasiswa 3 |

### Data Kelas & Nilai Awal:
- **Kelas 1 (`IF4101` - Keamanan Informasi):** Diampu oleh `dosen1`.
  - Nilai ID 1: `mhs1` (Nilai: 85.0 / A, belum final)
  - Nilai ID 2: `mhs2` (Nilai: 78.5 / B+, belum final)
  - Nilai ID 3: `mhs3` (Nilai: 68.0 / B-, belum final)
- **Kelas 2 (`IF4102` - Rekayasa Perangkat Lunak):** Diampu oleh `dosen2`.
  - Nilai ID 4: `mhs1` (Nilai: 88.0 / A, belum final)
  - Nilai ID 5: `mhs2` (Nilai: 91.0 / A, belum final)
  - Nilai ID 6: `mhs3` (Nilai: 74.0 / B, belum final)

---

## 4. Panduan Menjalankan Sistem

### A. Prasyarat
- Node.js versi 18, 20, 22 (LTS) atau 24+.
- npm versi 9+.

### B. Instalasi Dependensi
```bash
npm install
```

### C. Inisialisasi Database & Seeding
```bash
npm run db:init
```

### D. Menjalankan Layanan

Buka 3 terminal terpisah (atau gunakan script runner otomatis):

**Terminal 1 (Service Nilai - Port 3001):**
```bash
npm run start:nilai
```

**Terminal 2 (Service Transkrip - Port 3002):**
```bash
npm run start:transkrip
```

**Terminal 3 (API Gateway / PEP - Port 3000):**
```bash
npm run start:gateway
```

### E. Menjalankan Pengujian Otomatis End-to-End
Sistem dilengkapi dengan test runner yang menjalankan seluruh skenario pengujian secara otomatis:
```bash
node tests/test-runner.js
```

---

## 5. Skenario Pengujian Menggunakan `curl`

Berikut adalah kumpulan perintah `curl` lengkap untuk keperluan pengujian dan demonstrasi video.

### Skenario 1: Login & Verifikasi Device

#### 1.1 Login Mahasiswa 1 dengan Device Sah (Berhasil - 200 OK)
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-MHS-001" \
  -d '{"username":"mhs1","password":"mhs123"}'
```

#### 1.2 Login Mahasiswa 1 dengan Device Tidak Terdaftar (Ditolak - 403 Forbidden)
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-ASING-999" \
  -d '{"username":"mhs1","password":"mhs123"}'
```

#### 1.3 Login Dosen 1 (Simpan token untuk pengujian berikutnya)
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-DSN-001" \
  -d '{"username":"dosen1","password":"dosen123"}'
```

---

### Skenario 2: Proteksi Akses Langsung ke Service (Prinsip Assume Breach)

#### 2.1 Akses Langsung ke Service Nilai Port 3001 Tanpa Gateway Secret (Ditolak - 403 Forbidden)
```bash
curl -i -X GET http://localhost:3001/nilai \
  -H "Authorization: Bearer <TOKEN_DOSEN_1>"
```
*Respons:* Ditolak karena tidak membawa header `X-Gateway-Secret`.

#### 2.2 Akses Langsung Membawa Header Gateway Secret tapi Tanpa Token Valid (Ditolak - 401 Unauthorized)
```bash
curl -i -X GET http://localhost:3001/nilai \
  -H "X-Gateway-Secret: X-PEP-GATEWAY-INTERNAL-SECRET-AUTHENTICITY-KEY" \
  -H "Authorization: Bearer token-palsu-sembarangan"
```
*Respons:* Service memverifikasi ulang tanda tangan JWT secara mandiri (*Never trust blindly*).

---

### Skenario 3: Hak Akses Nilai (GET /nilai)

#### 3.1 Mahasiswa Mengambil Nilai (Hanya melihat nilai miliknya)
```bash
curl -X GET http://localhost:3000/nilai \
  -H "Authorization: Bearer <TOKEN_MHS_1>" \
  -H "X-Device-ID: DEV-MHS-001"
```

#### 3.2 Mahasiswa Menggunakan Device ID Milik Orang Lain (Ditolak - 403 Forbidden)
```bash
curl -X GET http://localhost:3000/nilai \
  -H "Authorization: Bearer <TOKEN_MHS_1>" \
  -H "X-Device-ID: DEV-DSN-001"
```

#### 3.3 Dosen 1 Mengambil Nilai (Hanya melihat kelas yang diampunya)
```bash
curl -X GET http://localhost:3000/nilai \
  -H "Authorization: Bearer <TOKEN_DOSEN_1>" \
  -H "X-Device-ID: DEV-DSN-001"
```

---

### Skenario 4: Pengubahan Nilai (PUT /nilai/:id) & Jam Akses

#### 4.1 Dosen 1 Mengubah Nilai Kelas yang Diampunya (Berhasil - 200 OK)
```bash
curl -X PUT http://localhost:3000/nilai/1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN_DOSEN_1>" \
  -H "X-Device-ID: DEV-DSN-001" \
  -d '{"nilai_angka": 95.0, "nilai_huruf": "A"}'
```

#### 4.2 Dosen 1 Mencoba Mengubah Nilai Kelas Dosen 2 (Ditolak - 403 Forbidden)
```bash
curl -X PUT http://localhost:3000/nilai/4 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN_DOSEN_1>" \
  -H "X-Device-ID: DEV-DSN-001" \
  -d '{"nilai_angka": 60.0, "nilai_huruf": "C"}'
```

#### 4.3 Mahasiswa Mencoba Mengubah Nilai (Ditolak - 403 Forbidden)
```bash
curl -X PUT http://localhost:3000/nilai/1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN_MHS_1>" \
  -H "X-Device-ID: DEV-MHS-001" \
  -d '{"nilai_angka": 100.0, "nilai_huruf": "A"}'
```

---

### Skenario 5: Finalisasi Kelas & Sinkronisasi Antar-Service

#### 5.1 Dosen 1 Memfinalisasi Kelas 1 (Berhasil - 200 OK)
```bash
curl -X POST http://localhost:3000/kelas/1/finalisasi \
  -H "Authorization: Bearer <TOKEN_DOSEN_1>" \
  -H "X-Device-ID: DEV-DSN-001"
```
*Alur di balik layar:* Service Nilai secara otomatis menghubungi Gateway (`POST /auth/service`) untuk mendapatkan Token Service, lalu memanggil `POST /transkrip/sinkron` via Gateway. Nilai mahasiswa otomatis tersinkron ke transkrip.

#### 5.2 Mencoba Mengubah Nilai yang Telah Difinalisasi (Ditolak - 403 Forbidden)
```bash
curl -X PUT http://localhost:3000/nilai/1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN_DOSEN_1>" \
  -H "X-Device-ID: DEV-DSN-001" \
  -d '{"nilai_angka": 70.0, "nilai_huruf": "B"}'
```

#### 5.3 User Biasa Mencoba Menembak Endpoint Sinkronisasi Secara Langsung (Ditolak - 403 Forbidden)
```bash
curl -X POST http://localhost:3000/transkrip/sinkron \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN_DOSEN_1>" \
  -H "X-Device-ID: DEV-DSN-001" \
  -d '{"kelas_id": 1, "items": []}'
```
*Respons:* Ditolak karena endpoint sinkronisasi HANYA menerima token service (`role: service`).

---

### Skenario 6: Hak Akses Transkrip (GET /transkrip/:nim)

#### 6.1 Mahasiswa 1 Melihat Transkrip Sendiri (Berhasil - 200 OK)
```bash
curl -X GET http://localhost:3000/transkrip/217006001 \
  -H "Authorization: Bearer <TOKEN_MHS_1>" \
  -H "X-Device-ID: DEV-MHS-001"
```

#### 6.2 Mahasiswa 1 Mencoba Mengintip Transkrip Mahasiswa 2 (Ditolak - 403 Forbidden)
```bash
curl -X GET http://localhost:3000/transkrip/217006002 \
  -H "Authorization: Bearer <TOKEN_MHS_1>" \
  -H "X-Device-ID: DEV-MHS-001"
```

#### 6.3 Admin Melihat Transkrip Mahasiswa Manapun (Berhasil - 200 OK)
```bash
curl -X GET http://localhost:3000/transkrip/217006001 \
  -H "Authorization: Bearer <TOKEN_ADMIN>" \
  -H "X-Device-ID: DEV-ADM-001"
```

---

### Skenario 7: Refresh Token & Logout

#### 7.1 Refresh Token (Memperoleh Access Token Baru)
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-MHS-001" \
  -d '{"refreshToken": "<REFRESH_TOKEN_MHS_1>"}'
```

#### 7.2 Logout (Mencabut Refresh Token di Database)
```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-MHS-001" \
  -d '{"refreshToken": "<REFRESH_TOKEN_MHS_1>"}'
```

#### 7.3 Menggunakan Kembali Refresh Token yang Telah Dicabut (Ditolak - 403 Forbidden)
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-MHS-001" \
  -d '{"refreshToken": "<REFRESH_TOKEN_MHS_1>"}'
```

---

### Skenario 8: Audit Log Telemetri

Melihat riwayat log keputusan PEP (ALLOW / DENY beserta alasan):
```bash
curl -X GET "http://localhost:3000/audit-logs?limit=20"
```
Atau query langsung ke database SQLite:
```bash
node -e "const db = require('./db/db'); console.table(db.prepare('SELECT id, timestamp, decision, method, endpoint, subject, reason FROM audit_logs ORDER BY id DESC LIMIT 15').all());"
```

---

## 6. Petunjuk Demonstrasi Video (Durasi 6–9 Menit)

Struktur penyampaian video demo yang direkomendasikan:
1. **0:00 - 1:00 | Pendahuluan & Arsitektur NIST SP 800-207:**
   - Tunjukkan diagram arsitektur sistem (API Gateway Port 3000 sebagai PEP, Service Nilai Port 3001, Service Transkrip Port 3002).
   - Jelaskan konsep *Never Trust, Always Verify*, *Least Privilege*, dan *Assume Breach*.
2. **1:00 - 2:30 | Autentikasi, Token, & Device Context:**
   - Perlihatkan kode `gateway/policy.js` (fungsi `loginUser` dan verifikasi device).
   - Demo login berhasil dengan device terdaftar vs login ditolak saat `X-Device-ID` diubah.
3. **2:30 - 4:00 | Proteksi Service & X-Gateway-Secret:**
   - Perlihatkan kode `services/nilai-service/middleware/verifyTrust.js`.
   - Demo penolakan request langsung ke port 3001 tanpa header `X-Gateway-Secret`.
4. **4:00 - 5:30 | Kontrol Akses Berbasis Kepemilikan Data & Jam Akses:**
   - Demo Dosen 1 melihat nilai kelasnya vs mencoba mengubah nilai kelas Dosen 2 (ditolak).
   - Demo pembatasan jam operasional akses.
5. **5:30 - 7:30 | Finalisasi Kelas & Panggilan Antar-Service M2M:**
   - Demo eksekusi `POST /kelas/1/finalisasi`.
   - Tunjukkan log terminal: Service Nilai meminta Service Token ke Gateway, lalu meneruskannya ke Service Transkrip.
   - Demo nilai mahasiswa terkunci dan otomatis muncul di `GET /transkrip/:nim`.
   - Demo penolakan jika user biasa memanggil `POST /transkrip/sinkron`.
6. **7:30 - 8:30 | Refresh Token, Logout, & Audit Log:**
   - Demo logout dan pencabutan token.
   - Tunjukkan isi tabel `audit_logs` di database.
