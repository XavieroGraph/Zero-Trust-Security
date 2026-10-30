const express = require('express');
const db = require('../../db/db');
const config = require('../../config');
const verifyTrust = require('./middleware/verifyTrust');

const app = express();
app.use(express.json());

// Terapkan Zero Trust Middleware pada seluruh endpoint resource Nilai
app.use(verifyTrust);

/**
 * GET /nilai
 * Mahasiswa: Hanya melihat nilai miliknya sendiri
 * Dosen: Hanya melihat nilai kelas yang diampunya
 */
app.get('/nilai', (req, res) => {
  const { sub, role, nim } = req.user;

  try {
    if (role === 'mahasiswa') {
      const rows = db.prepare(`
        SELECT 
          n.id AS nilai_id,
          k.id AS kelas_id,
          k.kode_mk,
          k.nama_mk,
          k.sks,
          u_dos.nama AS dosen_pengampu,
          n.nilai_angka,
          n.nilai_huruf,
          n.is_final
        FROM nilai n
        JOIN kelas k ON n.kelas_id = k.id
        JOIN users u_dos ON k.dosen_id = u_dos.id
        WHERE n.mahasiswa_id = ?
        ORDER BY k.kode_mk ASC
      `).all(sub);

      return res.json({
        success: true,
        message: 'Data nilai mahasiswa berhasil diambil.',
        user: { sub, role, nim },
        total: rows.length,
        data: rows
      });
    }

    if (role === 'dosen') {
      const rows = db.prepare(`
        SELECT 
          n.id AS nilai_id,
          k.id AS kelas_id,
          k.kode_mk,
          k.nama_mk,
          u_mhs.nim AS nim_mahasiswa,
          u_mhs.nama AS nama_mahasiswa,
          n.nilai_angka,
          n.nilai_huruf,
          n.is_final
        FROM nilai n
        JOIN kelas k ON n.kelas_id = k.id
        JOIN users u_mhs ON n.mahasiswa_id = u_mhs.id
        WHERE k.dosen_id = ?
        ORDER BY k.kode_mk ASC, u_mhs.nim ASC
      `).all(sub);

      return res.json({
        success: true,
        message: 'Data nilai kelas yang diampu dosen berhasil diambil.',
        user: { sub, role },
        total: rows.length,
        data: rows
      });
    }

    return res.status(403).json({
      success: false,
      error: 'Forbidden',
      message: 'Role Anda tidak memiliki akses ke data nilai.'
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * PUT /nilai/:id
 * Dosen: Mengubah nilai mahasiswa pada kelas yang diampu (belum final)
 */
app.put('/nilai/:id', (req, res) => {
  const nilaiId = parseInt(req.params.id, 10);
  const { sub, role } = req.user;
  const { nilai_angka, nilai_huruf } = req.body;

  if (role !== 'dosen') {
    return res.status(403).json({
      success: false,
      error: 'Forbidden',
      message: 'Hanya Dosen yang berhak mengubah data nilai.'
    });
  }

  if (nilai_angka === undefined || !nilai_huruf) {
    return res.status(400).json({
      success: false,
      error: 'Bad Request',
      message: 'Field nilai_angka dan nilai_huruf wajib disertakan.'
    });
  }

  try {
    const record = db.prepare(`
      SELECT n.id, n.is_final AS nilai_is_final, k.is_final AS kelas_is_final, k.dosen_id, k.nama_mk
      FROM nilai n
      JOIN kelas k ON n.kelas_id = k.id
      WHERE n.id = ?
    `).get(nilaiId);

    if (!record) {
      return res.status(404).json({ success: false, error: 'Data nilai tidak ditemukan.' });
    }

    if (record.dosen_id !== sub) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden',
        message: 'Anda bukan dosen pengampu untuk kelas nilai ini.'
      });
    }

    if (record.nilai_is_final === 1 || record.kelas_is_final === 1) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden',
        message: 'Nilai sudah final dan tidak dapat diubah.'
      });
    }

    // Update nilai
    db.prepare(`
      UPDATE nilai 
      SET nilai_angka = ?, nilai_huruf = ?, updated_at = datetime('now', 'localtime')
      WHERE id = ?
    `).run(nilai_angka, nilai_huruf, nilaiId);

    const updated = db.prepare(`
      SELECT n.*, u.nama AS nama_mahasiswa, u.nim, k.nama_mk 
      FROM nilai n
      JOIN users u ON n.mahasiswa_id = u.id
      JOIN kelas k ON n.kelas_id = k.id
      WHERE n.id = ?
    `).get(nilaiId);

    return res.json({
      success: true,
      message: 'Data nilai berhasil diperbarui.',
      data: updated
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /kelas/:id/finalisasi
 * Dosen: Memfinalisasi nilai kelas yang diampu, lalu memicu sinkron transkrip
 * ke Service Transkrip melalui API Gateway menggunakan Token Service (M2M).
 */
app.post('/kelas/:id/finalisasi', async (req, res) => {
  const kelasId = parseInt(req.params.id, 10);
  const { sub, role } = req.user;

  if (role !== 'dosen') {
    return res.status(403).json({
      success: false,
      error: 'Forbidden',
      message: 'Hanya Dosen yang berhak memfinalisasi kelas.'
    });
  }

  try {
    const kelas = db.prepare(`SELECT * FROM kelas WHERE id = ?`).get(kelasId);
    if (!kelas) {
      return res.status(404).json({ success: false, error: 'Kelas tidak ditemukan.' });
    }

    if (kelas.dosen_id !== sub) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden',
        message: 'Anda bukan dosen pengampu kelas ini.'
      });
    }

    if (kelas.is_final === 1) {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
        message: 'Kelas ini sudah difinalisasi sebelumnya.'
      });
    }

    // 1. Update status finalisasi di database
    db.prepare('UPDATE kelas SET is_final = 1 WHERE id = ?').run(kelasId);
    db.prepare('UPDATE nilai SET is_final = 1 WHERE kelas_id = ?').run(kelasId);

    // 2. Ambil data nilai lengkap untuk disinkronkan ke transkrip
    const nilaiFinal = db.prepare(`
      SELECT 
        n.mahasiswa_id,
        u.nim,
        k.kode_mk,
        k.nama_mk,
        k.sks,
        n.nilai_huruf
      FROM nilai n
      JOIN users u ON n.mahasiswa_id = u.id
      JOIN kelas k ON n.kelas_id = k.id
      WHERE n.kelas_id = ?
    `).all(kelasId);

    console.log(`[Service Nilai] Memulai sinkronisasi ${nilaiFinal.length} nilai kelas '${kelas.nama_mk}' ke Service Transkrip via Gateway...`);

    // 3. Permintaan Token Service ke API Gateway (Port 3000)
    const clientCreds = config.SERVICE_CLIENTS['service-nilai'];
    const authRes = await fetch(`http://localhost:${config.PORT_GATEWAY}/auth/service`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        clientId: 'service-nilai',
        clientSecret: clientCreds.secret
      })
    });

    const authData = await authRes.json();
    const serviceToken = authData.serviceToken || authData.data?.serviceToken;
    if (!authRes.ok || !serviceToken) {
      throw new Error(`Gagal memperoleh Token Service dari Gateway: ${authData.error || authData.message || authRes.statusText}`);
    }
    console.log('[Service Nilai] Berhasil memperoleh Token Service dari Gateway.');

    // 4. Panggil Service Transkrip melalui API Gateway (Port 3000)
    // Sesuai prinsip Zero Trust: Komunikasi antar-service tetap melewati PEP Gateway
    const syncRes = await fetch(`http://localhost:${config.PORT_GATEWAY}/transkrip/sinkron`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`
      },
      body: JSON.stringify({
        kelas_id: kelasId,
        items: nilaiFinal
      })
    });

    const syncData = await syncRes.json();
    if (!syncRes.ok) {
      throw new Error(`Sinkronisasi ke Service Transkrip ditolak Gateway/Service: ${syncData.reason || syncData.message || syncRes.statusText}`);
    }

    console.log('[Service Nilai] Sinkronisasi transkrip berhasil diselesaikan via Gateway.');

    return res.json({
      success: true,
      message: `Kelas '${kelas.nama_mk}' berhasil difinalisasi dan transkrip mahasiswa telah disinkronkan.`,
      kelas: {
        id: kelas.id,
        kode_mk: kelas.kode_mk,
        nama_mk: kelas.nama_mk,
        is_final: 1
      },
      sinkronisasi: syncData
    });

  } catch (err) {
    console.error('[Service Nilai Error]', err.message);
    return res.status(500).json({
      success: false,
      error: 'Finalisasi Gagal',
      details: err.message
    });
  }
});

// Menjalankan Service Nilai
const server = app.listen(config.PORT_NILAI, () => {
  console.log(`✔ [Service Nilai] Berjalan di port ${config.PORT_NILAI} (Internal Service)`);
});

module.exports = { app, server };
