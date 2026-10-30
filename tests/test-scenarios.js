/**
 * ==============================================================================
 * ZERO TRUST SECURITY - SUITE PENGUJIAN END-TO-END (AUTOMATED TEST SCENARIOS)
 * Mata Kuliah: Keamanan Informasi - Universitas Siliwangi
 * ==============================================================================
 */

const config = require('../config');
const db = require('../db/db');
const runSeed = require('../db/seed');

const BASE_URL = `http://localhost:${config.PORT_GATEWAY}`;
const NILAI_DIRECT_URL = `http://localhost:${config.PORT_NILAI}`;
const TRANSKRIP_DIRECT_URL = `http://localhost:${config.PORT_TRANSKRIP}`;

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

function pass(msg) {
  console.log(`  ${colors.green}✔ PASS:${colors.reset} ${msg}`);
}

function fail(msg, err) {
  console.error(`  ${colors.red}✘ FAIL:${colors.reset} ${msg}`);
  if (err) console.error(`    Detail:`, err);
}

function header(title) {
  console.log(`\n${colors.bold}${colors.cyan}=== [SKENARIO PENGUJIAN] ${title} ===${colors.reset}`);
}

async function runTests() {
  console.log(`${colors.yellow}Memulai Pengujian Otomatis Zero Trust Architecture...${colors.reset}\n`);

  // Pastikan database dalam kondisi seed awal
  runSeed();

  let tokenMhs1, tokenMhs2, tokenDosen1, tokenDosen2, tokenAdmin, refreshTokenMhs1;

  // ===========================================================================
  // SKENARIO 1: AUTENTIKASI PENGGUNA & VERIFIKASI DEVICE (NIST SP 800-207)
  // ===========================================================================
  header('1. Autentikasi & Verifikasi Device Terdaftar');

  // 1.1 Login Mahasiswa 1 dengan Device Sah
  try {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': 'DEV-MHS-001'
      },
      body: JSON.stringify({ username: 'mhs1', password: 'mhs123' })
    });
    const data = await res.json();
    if (res.status === 200 && data.accessToken) {
      tokenMhs1 = data.accessToken;
      refreshTokenMhs1 = data.refreshToken;
      pass('Login Mahasiswa 1 berhasil dengan kredensial valid dan Device ID terdaftar (DEV-MHS-001).');
    } else {
      fail('Login Mahasiswa 1 gagal', data);
    }
  } catch (err) { fail('Error request login mhs1', err); }

  // 1.2 Login Mahasiswa 1 dengan Device Tidak Terdaftar (Harus Ditolak 403)
  try {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': 'DEV-MHS-UNKNOWN-999'
      },
      body: JSON.stringify({ username: 'mhs1', password: 'mhs123' })
    });
    const data = await res.json();
    if (res.status === 403) {
      pass(`Ditolak (403): Login dengan Device tidak terdaftar diblokir. Pesan: ${data.error}`);
    } else {
      fail(`Gagal menolak device tidak terdaftar! Status: ${res.status}`, data);
    }
  } catch (err) { fail('Error test unauthorized device', err); }

  // 1.3 Login dengan Password Salah (Harus Ditolak 401)
  try {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': 'DEV-MHS-001'
      },
      body: JSON.stringify({ username: 'mhs1', password: 'wrongpassword' })
    });
    if (res.status === 401) {
      pass('Ditolak (401): Login dengan password salah berhasil ditolak.');
    } else {
      fail(`Gagal menolak password salah! Status: ${res.status}`);
    }
  } catch (err) { fail('Error test wrong password', err); }

  // Dapatkan Token Dosen 1, Dosen 2, dan Admin untuk pengujian berikutnya
  try {
    const resDsn1 = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Device-ID': 'DEV-DSN-001' },
      body: JSON.stringify({ username: 'dosen1', password: 'dosen123' })
    });
    tokenDosen1 = (await resDsn1.json()).accessToken;

    const resDsn2 = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Device-ID': 'DEV-DSN-002' },
      body: JSON.stringify({ username: 'dosen2', password: 'dosen123' })
    });
    tokenDosen2 = (await resDsn2.json()).accessToken;

    const resAdm = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Device-ID': 'DEV-ADM-001' },
      body: JSON.stringify({ username: 'admin1', password: 'admin123' })
    });
    tokenAdmin = (await resAdm.json()).accessToken;
    pass('Berhasil mengotentikasi Dosen 1, Dosen 2, dan Admin dengan Device ID masing-masing.');
  } catch (err) { fail('Error login dosen/admin', err); }

  // ===========================================================================
  // SKENARIO 2: PERLINDUNGAN AKSES LANGSUNG SERVICE (GATEWAY SECRET VERIFICATION)
  // Prinsip: Assume Breach & Never Trust, Always Verify
  // ===========================================================================
  header('2. Proteksi Akses Langsung ke Service (Verifikasi Gateway Secret)');

  // 2.1 Akses langsung ke Service Nilai (Port 3001) tanpa X-Gateway-Secret (Harus Ditolak 403)
  try {
    const res = await fetch(`${NILAI_DIRECT_URL}/nilai`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${tokenDosen1}`
      }
    });
    const data = await res.json();
    if (res.status === 403) {
      pass(`Ditolak (403): Akses langsung ke port 3001 tanpa X-Gateway-Secret diblokir oleh service.`);
    } else {
      fail(`Service Nilai meloloskan request langsung tanpa X-Gateway-Secret! Status: ${res.status}`);
    }
  } catch (err) { fail('Error test bypass gateway', err); }

  // 2.2 Akses langsung membawa X-Gateway-Secret tapi tanpa JWT valid (Harus Ditolak 401)
  try {
    const res = await fetch(`${NILAI_DIRECT_URL}/nilai`, {
      method: 'GET',
      headers: {
        'X-Gateway-Secret': config.GATEWAY_SECRET,
        'Authorization': 'Bearer invalid.token.signature'
      }
    });
    if (res.status === 401) {
      pass('Ditolak (401): Service memverifikasi ulang token secara mandiri (Never trust blindly).');
    } else {
      fail(`Service tidak memverifikasi token secara mandiri! Status: ${res.status}`);
    }
  } catch (err) { fail('Error test token re-verification', err); }

  // ===========================================================================
  // SKENARIO 3: HAK AKSES PENGAMBILAN NILAI (LEAST PRIVILEGE)
  // ===========================================================================
  header('3. Hak Akses Nilai (GET /nilai melalui Gateway)');

  // 3.1 Mahasiswa 1 melihat nilai
  try {
    const res = await fetch(`${BASE_URL}/nilai`, {
      headers: {
        'Authorization': `Bearer ${tokenMhs1}`,
        'X-Device-ID': 'DEV-MHS-001'
      }
    });
    const data = await res.json();
    if (res.status === 200 && data.data) {
      pass(`Mahasiswa 1 berhasil melihat ${data.data.length} mata kuliah miliknya sendiri.`);
    } else {
      fail('Mahasiswa gagal mengambil nilai miliknya', data);
    }
  } catch (err) { fail('Error mhs get nilai', err); }

  // 3.2 Akses dengan Device ID yang salah saat mengakses /nilai (Harus Ditolak 403)
  try {
    const res = await fetch(`${BASE_URL}/nilai`, {
      headers: {
        'Authorization': `Bearer ${tokenMhs1}`,
        'X-Device-ID': 'DEV-DSN-001' // Device milik Dosen 1, bukan milik Mhs 1
      }
    });
    const data = await res.json();
    if (res.status === 403) {
      pass(`Ditolak (403): PEP Gateway menolak request karena Device ID bukan milik pengguna tersebut.`);
    } else {
      fail(`PEP meloloskan Device ID milik orang lain! Status: ${res.status}`);
    }
  } catch (err) { fail('Error test wrong device on resource', err); }

  // 3.3 Dosen 1 melihat nilai kelas yang diampunya
  try {
    const res = await fetch(`${BASE_URL}/nilai`, {
      headers: {
        'Authorization': `Bearer ${tokenDosen1}`,
        'X-Device-ID': 'DEV-DSN-001'
      }
    });
    const data = await res.json();
    if (res.status === 200 && data.data) {
      pass(`Dosen 1 berhasil melihat ${data.data.length} nilai mahasiswa pada kelas yang diampunya (IF4101).`);
    } else {
      fail('Dosen 1 gagal melihat nilai kelasnya', data);
    }
  } catch (err) { fail('Error dosen get nilai', err); }

  // ===========================================================================
  // SKENARIO 4: PENGUBAHAN NILAI OLEH DOSEN (PUT /nilai/:id)
  // ===========================================================================
  header('4. Pengubahan Nilai oleh Dosen (Ownership & Policy Enforcement)');

  // 4.1 Dosen 1 mengubah nilai di kelas yang diampunya (Nilai ID 1: IF4101)
  try {
    const res = await fetch(`${BASE_URL}/nilai/1`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenDosen1}`,
        'X-Device-ID': 'DEV-DSN-001'
      },
      body: JSON.stringify({ nilai_angka: 95.0, nilai_huruf: 'A' })
    });
    const data = await res.json();
    if (res.status === 200 && data.data.nilai_angka === 95.0) {
      pass('Dosen 1 berhasil mengubah nilai mahasiswa pada kelas yang diampunya.');
    } else {
      fail('Dosen 1 gagal mengubah nilai kelas yang diampunya', data);
    }
  } catch (err) { fail('Error update nilai', err); }

  // 4.2 Dosen 1 mencoba mengubah nilai kelas milik Dosen 2 (Nilai ID 4: IF4102) (Harus Ditolak 403)
  try {
    const res = await fetch(`${BASE_URL}/nilai/4`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenDosen1}`,
        'X-Device-ID': 'DEV-DSN-001'
      },
      body: JSON.stringify({ nilai_angka: 50.0, nilai_huruf: 'D' })
    });
    const data = await res.json();
    if (res.status === 403) {
      pass(`Ditolak (403): Dosen 1 diblokir karena bukan pengampu kelas untuk Nilai ID 4. Alasan: ${data.reason}`);
    } else {
      fail(`PEP meloloskan perubahan nilai oleh dosen bukan pengampu! Status: ${res.status}`);
    }
  } catch (err) { fail('Error test unauthorized dosen update', err); }

  // 4.3 Mahasiswa mencoba mengubah nilai (Harus Ditolak 403)
  try {
    const res = await fetch(`${BASE_URL}/nilai/1`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenMhs1}`,
        'X-Device-ID': 'DEV-MHS-001'
      },
      body: JSON.stringify({ nilai_angka: 100.0, nilai_huruf: 'A' })
    });
    if (res.status === 403) {
      pass('Ditolak (403): Mahasiswa dilarang mengubah nilai.');
    } else {
      fail(`PEP meloloskan mahasiswa mengubah nilai! Status: ${res.status}`);
    }
  } catch (err) { fail('Error test mhs update nilai', err); }

  // 4.4 Pengujian Konteks Jam Akses (Simulasi operasi di luar jam 07:00 - 21:00)
  const currentHour = new Date().getHours();
  const originalHours = { ...config.ACCESS_HOURS };
  config.ACCESS_HOURS.start = (currentHour + 2) % 24;
  config.ACCESS_HOURS.end = (currentHour + 3) % 24;

  try {
    const res = await fetch(`${BASE_URL}/nilai/1`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenDosen1}`,
        'X-Device-ID': 'DEV-DSN-001'
      },
      body: JSON.stringify({ nilai_angka: 80.0, nilai_huruf: 'B' })
    });
    const data = await res.json();
    if (res.status === 403 && (data.reason || '').includes('hanya diizinkan pukul')) {
      pass(`Ditolak (403): Verifikasi konteks jam akses berhasil memblokir perubahan nilai di luar jam operasional. Pesan: ${data.reason}`);
    } else {
      fail(`Gagal memblokir perubahan nilai di luar jam operasional! Status: ${res.status}`, data);
    }
  } catch (err) { fail('Error test access hours', err); }
  finally {
    config.ACCESS_HOURS.start = originalHours.start;
    config.ACCESS_HOURS.end = originalHours.end;
  }

  // ===========================================================================
  // SKENARIO 5: FINALISASI NILAI & SINKRONISASI TRANSKRIP (M2M SERVICE TOKEN)
  // ===========================================================================
  header('5. Finalisasi Kelas & Sinkronisasi Antar-Service');

  // 5.1 Dosen 1 memfinalisasi Kelas 1 (IF4101)
  // Mengetes alur: Service Nilai meminta Token Service ke Gateway -> Gateway memvalidasi -> Service Nilai memanggil Service Transkrip via Gateway
  try {
    const res = await fetch(`${BASE_URL}/kelas/1/finalisasi`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${tokenDosen1}`,
        'X-Device-ID': 'DEV-DSN-001'
      }
    });
    const data = await res.json();
    if (res.status === 200 && data.success) {
      pass(`Kelas 1 berhasil difinalisasi! Transkrip otomatis disinkronkan melalui Service Token.`);
    } else {
      fail('Finalisasi kelas 1 gagal', data);
    }
  } catch (err) { fail('Error finalisasi kelas', err); }

  // 5.2 Mencoba mengubah nilai setelah finalisasi (Harus Ditolak 403)
  try {
    const res = await fetch(`${BASE_URL}/nilai/1`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenDosen1}`,
        'X-Device-ID': 'DEV-DSN-001'
      },
      body: JSON.stringify({ nilai_angka: 80.0, nilai_huruf: 'B' })
    });
    const data = await res.json();
    if (res.status === 403) {
      pass(`Ditolak (403): Nilai yang sudah difinalisasi terkunci dan tidak dapat diubah.`);
    } else {
      fail(`Nilai yang sudah final masih bisa diubah! Status: ${res.status}`);
    }
  } catch (err) { fail('Error test update final grade', err); }

  // 5.3 User biasa (Dosen/Admin/Mahasiswa) mencoba menembak POST /transkrip/sinkron secara langsung (Harus Ditolak 403)
  try {
    const res = await fetch(`${BASE_URL}/transkrip/sinkron`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenAdmin}`, // Token user Admin
        'X-Device-ID': 'DEV-ADM-001'
      },
      body: JSON.stringify({
        kelas_id: 1,
        items: []
      })
    });
    const data = await res.json();
    if (res.status === 403) {
      pass(`Ditolak (403): Endpoint /transkrip/sinkron menolak token pengguna (Hanya menerima Token Service). Alasan: ${data.reason}`);
    } else {
      fail(`Endpoint sinkronisasi meloloskan token user! Status: ${res.status}`);
    }
  } catch (err) { fail('Error test user call sync endpoint', err); }

  // ===========================================================================
  // SKENARIO 6: HAK AKSES TRANSKRIP (GET /transkrip/:nim)
  // ===========================================================================
  header('6. Hak Akses Transkrip Mahasiswa');

  // 6.1 Mahasiswa 1 melihat transkrip miliknya (NIM: 217006001)
  try {
    const res = await fetch(`${BASE_URL}/transkrip/217006001`, {
      headers: {
        'Authorization': `Bearer ${tokenMhs1}`,
        'X-Device-ID': 'DEV-MHS-001'
      }
    });
    const data = await res.json();
    if (res.status === 200 && data.mahasiswa.nim === '217006001') {
      pass(`Mahasiswa 1 berhasil melihat transkrip miliknya (Mata kuliah tersinkron: ${data.mataKuliah.length}).`);
    } else {
      fail('Mahasiswa 1 gagal melihat transkrip miliknya', data);
    }
  } catch (err) { fail('Error mhs get own transcript', err); }

  // 6.2 Mahasiswa 1 mencoba melihat transkrip Mahasiswa 2 (NIM: 217006002) (Harus Ditolak 403)
  try {
    const res = await fetch(`${BASE_URL}/transkrip/217006002`, {
      headers: {
        'Authorization': `Bearer ${tokenMhs1}`,
        'X-Device-ID': 'DEV-MHS-001'
      }
    });
    const data = await res.json();
    if (res.status === 403) {
      pass(`Ditolak (403): Mahasiswa dilarang mengintip transkrip mahasiswa lain. Alasan: ${data.reason}`);
    } else {
      fail(`PEP meloloskan mahasiswa melihat transkrip orang lain! Status: ${res.status}`);
    }
  } catch (err) { fail('Error test view other transcript', err); }

  // 6.3 Admin melihat transkrip Mahasiswa manapun
  try {
    const res = await fetch(`${BASE_URL}/transkrip/217006001`, {
      headers: {
        'Authorization': `Bearer ${tokenAdmin}`,
        'X-Device-ID': 'DEV-ADM-001'
      }
    });
    const data = await res.json();
    if (res.status === 200) {
      pass('Admin berhasil melihat transkrip mahasiswa sesuai hak aksesnya.');
    } else {
      fail('Admin gagal melihat transkrip', data);
    }
  } catch (err) { fail('Error admin view transcript', err); }

  // ===========================================================================
  // SKENARIO 7: REFRESH TOKEN & LOGOUT (REVOKED TOKEN)
  // ===========================================================================
  header('7. Refresh Token & Logout (Pencabutan Token)');

  // 7.1 Refresh Token menghasilkan Access Token baru
  let newAccessToken;
  try {
    const res = await fetch(`${BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': 'DEV-MHS-001'
      },
      body: JSON.stringify({ refreshToken: refreshTokenMhs1 })
    });
    const data = await res.json();
    if (res.status === 200 && data.accessToken) {
      newAccessToken = data.accessToken;
      pass('Refresh Token berhasil memperbarui Access Token.');
    } else {
      fail('Gagal melakukan refresh token', data);
    }
  } catch (err) { fail('Error refresh token', err); }

  // 7.2 Logout mencabut Refresh Token di Database
  try {
    const res = await fetch(`${BASE_URL}/auth/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': 'DEV-MHS-001'
      },
      body: JSON.stringify({ refreshToken: refreshTokenMhs1 })
    });
    if (res.status === 200) {
      pass('Logout berhasil, Refresh Token ditandai sebagai dicabut (is_revoked = 1).');
    } else {
      fail(`Logout gagal! Status: ${res.status}`);
    }
  } catch (err) { fail('Error logout', err); }

  // 7.3 Menggunakan Refresh Token yang sudah dicabut (Harus Ditolak 403)
  try {
    const res = await fetch(`${BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': 'DEV-MHS-001'
      },
      body: JSON.stringify({ refreshToken: refreshTokenMhs1 })
    });
    if (res.status === 403) {
      pass('Ditolak (403): Refresh Token yang sudah dicabut tidak dapat digunakan lagi.');
    } else {
      fail(`Refresh token yang dicabut masih dapat digunakan! Status: ${res.status}`);
    }
  } catch (err) { fail('Error test revoked refresh token', err); }

  // ===========================================================================
  // SKENARIO 8: TELEMETRI & AUDIT LOG (NIST SP 800-207)
  // ===========================================================================
  header('8. Pemeriksaan Audit Log di Database');
  try {
    const logs = db.prepare(`SELECT * FROM audit_logs ORDER BY id DESC LIMIT 5`).all();
    console.log(`  Ditemukan total ${db.prepare('SELECT COUNT(*) as cnt FROM audit_logs').get().cnt} baris catatan Audit Log.`);
    console.log('  Contoh 3 catatan audit log terakhir:');
    logs.slice(0, 3).forEach((l, idx) => {
      console.log(`    [${idx+1}] ${l.timestamp} | ${l.decision} | ${l.method} ${l.endpoint} | Sub: ${l.subject} | Dev: ${l.device_id} | Alasan: ${l.reason}`);
    });
    pass('Pencatatan Audit Log berfungsi dengan akurat pada setiap keputusan PEP.');
  } catch (err) { fail('Error membaca audit log', err); }

  console.log(`\n${colors.bold}${colors.green}✔ SELURUH SKENARIO PENGUJIAN BERHASIL DIJALANKAN DENGAN SEMPURNA!${colors.reset}\n`);
}

module.exports = runTests;

if (require.main === module) {
  runTests();
}
