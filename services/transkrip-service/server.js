const express = require('express');
const db = require('../../db/db');
const config = require('../../config');
const verifyTrust = require('./middleware/verifyTrust');

const app = express();
app.use(express.json());

// Terapkan Zero Trust Middleware pada seluruh endpoint resource Transkrip
app.use(verifyTrust);

// Helper konversi nilai huruf ke bobot IPK
function bobotNilai(huruf) {
  switch ((huruf || '').toUpperCase()) {
    case 'A': return 4.0;
    case 'B+': return 3.5;
    case 'B': return 3.0;
    case 'B-': return 2.75;
    case 'C+': return 2.5;
    case 'C': return 2.0;
    case 'D': return 1.0;
    default: return 0.0;
  }
}

/**
 * GET /transkrip/:nim
 * Mahasiswa: Hanya NIM sendiri
 * Admin: Seluruh NIM
 */
app.get('/transkrip/:nim', (req, res) => {
  const requestedNim = req.params.nim;
  const { role, nim: userNim } = req.user;

  try {
    // Verifikasi kepemilikan NIM untuk Mahasiswa (Defense in depth)
    if (role === 'mahasiswa' && userNim !== requestedNim) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden',
        message: 'Mahasiswa dilarang melihat transkrip milik mahasiswa lain.'
      });
    }

    const mahasiswa = db.prepare("SELECT id, nama, nim FROM users WHERE nim = ? AND role = 'mahasiswa'").get(requestedNim);
    if (!mahasiswa) {
      return res.status(404).json({
        success: false,
        error: 'Not Found',
        message: `Data mahasiswa dengan NIM ${requestedNim} tidak ditemukan.`
      });
    }

    const transkripList = db.prepare(`
      SELECT kode_mk, nama_mk, sks, nilai_huruf, synced_at
      FROM transkrip
      WHERE nim = ?
      ORDER BY kode_mk ASC
    `).all(requestedNim);

    // Hitung total SKS dan IPK
    let totalSks = 0;
    let totalBobot = 0;
    for (const item of transkripList) {
      totalSks += item.sks;
      totalBobot += item.sks * bobotNilai(item.nilai_huruf);
    }
    const ipk = totalSks > 0 ? (totalBobot / totalSks).toFixed(2) : '0.00';

    return res.json({
      success: true,
      message: 'Data transkrip akademik berhasil diambil.',
      aksesOleh: { role, subjek: req.user.username || req.user.sub },
      mahasiswa: {
        nim: mahasiswa.nim,
        nama: mahasiswa.nama,
        totalSks,
        ipk
      },
      mataKuliah: transkripList
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /transkrip/sinkron
 * HANYA menerima Token Service (role: service)
 * Seluruh token user (admin, dosen, mahasiswa) ditolak
 */
app.post('/transkrip/sinkron', (req, res) => {
  const { role, sub } = req.user;

  // Verifikasi otorisasi eksplisit Zero Trust (Defense-in-depth)
  if (role !== 'service') {
    return res.status(403).json({
      success: false,
      error: 'Forbidden (Zero Trust Policy)',
      message: `Akses ditolak: Endpoint ini hanya diizinkan untuk internal service token. Token role '${role}' tidak memiliki izin.`
    });
  }

  const { kelas_id, items } = req.body;
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Bad Request',
      message: 'Array data items nilai wajib disertakan.'
    });
  }

  try {
    const upsertStmt = db.prepare(`
      INSERT INTO transkrip (mahasiswa_id, nim, kode_mk, nama_mk, sks, nilai_huruf, synced_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
      ON CONFLICT(nim, kode_mk) DO UPDATE SET
        nilai_huruf = excluded.nilai_huruf,
        synced_at = datetime('now', 'localtime')
    `);

    let syncedCount = 0;
    for (const item of items) {
      upsertStmt.run(
        item.mahasiswa_id,
        item.nim,
        item.kode_mk,
        item.nama_mk,
        item.sks,
        item.nilai_huruf
      );
      syncedCount++;
    }

    console.log(`[Service Transkrip] Berhasil mensinkronkan ${syncedCount} record transkrip dari service '${sub}'.`);

    return res.json({
      success: true,
      message: 'Sinkronisasi transkrip berhasil diproses ke database.',
      callerService: sub,
      kelas_id,
      totalSynced: syncedCount,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('[Service Transkrip Error]', err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Menjalankan Service Transkrip
const server = app.listen(config.PORT_TRANSKRIP, () => {
  console.log(`✔ [Service Transkrip] Berjalan di port ${config.PORT_TRANSKRIP} (Internal Service)`);
});

module.exports = { app, server };
