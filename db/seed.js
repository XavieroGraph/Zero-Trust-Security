const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const db = require('./db');

function runSeed() {
  console.log('--- Inisialisasi Skema & Database Seeding (Zero Trust System) ---');

  // 1. Eksekusi Skema DDL
  const schemaPath = path.join(__dirname, 'schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf8');
  db.exec(schemaSql);
  console.log('✔ Skema database berhasil dieksekusi.');

  // 2. Bersihkan data lama (idempotent seed)
  db.exec(`
    DELETE FROM audit_logs;
    DELETE FROM transkrip;
    DELETE FROM nilai;
    DELETE FROM kelas;
    DELETE FROM refresh_tokens;
    DELETE FROM devices;
    DELETE FROM users;
    DELETE FROM sqlite_sequence;
  `);

  // 3. Helper Hash Password
  const hash = (pwd) => bcrypt.hashSync(pwd, 10);

  // 4. Data Pengguna (1 Admin, 2 Dosen, 3 Mahasiswa)
  const insertUser = db.prepare(`
    INSERT INTO users (username, password, nama, role, nim, nidn)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const users = [
    { username: 'admin1', pwd: hash('admin123'), name: 'Budi Santoso, M.Kom. (Admin TI)', role: 'admin', nim: null, nidn: null },
    { username: 'dosen1', pwd: hash('dosen123'), name: 'Dr. Husni Mubarok, M.T.', role: 'dosen', nim: null, nidn: '0412058001' },
    { username: 'dosen2', pwd: hash('dosen123'), name: 'Alam Rahmatulloh, M.T.', role: 'dosen', nim: null, nidn: '0418088502' },
    { username: 'mhs1', pwd: hash('mhs123'), name: 'Ahmad Fauzi', role: 'mahasiswa', nim: '217006001', nidn: null },
    { username: 'mhs2', pwd: hash('mhs123'), name: 'Siti Nurhaliza', role: 'mahasiswa', nim: '217006002', nidn: null },
    { username: 'mhs3', pwd: hash('mhs123'), name: 'Rian Hidayat', role: 'mahasiswa', nim: '217006003', nidn: null }
  ];

  const userIds = {};
  for (const u of users) {
    const info = insertUser.run(u.username, u.pwd, u.name, u.role, u.nim, u.nidn);
    userIds[u.username] = info.lastInsertRowid;
  }
  console.log('✔ Berhasil membuat 6 user (1 Admin, 2 Dosen, 3 Mahasiswa).');

  // 5. Data Device Terdaftar (X-Device-ID)
  // NIST SP 800-207: Device context validation
  const insertDevice = db.prepare(`
    INSERT INTO devices (user_id, device_id, device_name, is_active)
    VALUES (?, ?, ?, 1)
  `);

  const devices = [
    { username: 'admin1', device_id: 'DEV-ADM-001', name: 'Workstation Admin Biro TI' },
    { username: 'dosen1', device_id: 'DEV-DSN-001', name: 'MacBook Pro Dosen 1' },
    { username: 'dosen2', device_id: 'DEV-DSN-002', name: 'ThinkPad T14 Dosen 2' },
    { username: 'mhs1', device_id: 'DEV-MHS-001', name: 'Laptop Asus Mahasiswa 1' },
    { username: 'mhs2', device_id: 'DEV-MHS-002', name: 'Laptop Lenovo Mahasiswa 2' },
    { username: 'mhs3', device_id: 'DEV-MHS-003', name: 'Laptop Dell Mahasiswa 3' }
  ];

  for (const d of devices) {
    insertDevice.run(userIds[d.username], d.device_id, d.name);
  }
  console.log('✔ Berhasil mendaftarkan Device ID untuk setiap user.');

  // 6. Data Kelas (2 Kelas diampu oleh Dosen berbeda)
  const insertKelas = db.prepare(`
    INSERT INTO kelas (kode_mk, nama_mk, sks, dosen_id, is_final)
    VALUES (?, ?, ?, ?, 0)
  `);

  const kelas1Info = insertKelas.run('IF4101', 'Keamanan Informasi', 3, userIds['dosen1']);
  const kelas2Info = insertKelas.run('IF4102', 'Rekayasa Perangkat Lunak', 3, userIds['dosen2']);
  const kelas1Id = kelas1Info.lastInsertRowid;
  const kelas2Id = kelas2Info.lastInsertRowid;
  console.log(`✔ Berhasil membuat Kelas: IF4101 (Dosen 1, ID: ${kelas1Id}) dan IF4102 (Dosen 2, ID: ${kelas2Id}).`);

  // 7. Data Nilai Awal Mahasiswa (Belum Final)
  const insertNilai = db.prepare(`
    INSERT INTO nilai (kelas_id, mahasiswa_id, nilai_angka, nilai_huruf, is_final)
    VALUES (?, ?, ?, ?, 0)
  `);

  // Nilai di Kelas 1 (Keamanan Informasi - Dosen 1)
  insertNilai.run(kelas1Id, userIds['mhs1'], 85.0, 'A');
  insertNilai.run(kelas1Id, userIds['mhs2'], 78.5, 'B+');
  insertNilai.run(kelas1Id, userIds['mhs3'], 68.0, 'B-');

  // Nilai di Kelas 2 (Rekayasa Perangkat Lunak - Dosen 2)
  insertNilai.run(kelas2Id, userIds['mhs1'], 88.0, 'A');
  insertNilai.run(kelas2Id, userIds['mhs2'], 91.0, 'A');
  insertNilai.run(kelas2Id, userIds['mhs3'], 74.0, 'B');

  console.log('✔ Berhasil memasukkan data nilai awal untuk seluruh mahasiswa.');
  console.log('✔ Seeding database selesai. Sistem siap digunakan!\n');
}

if (require.main === module) {
  runSeed();
  db.close();
  process.exit(0);
}

module.exports = runSeed;
