const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../db/db');
const config = require('../config');

class PolicyEngine {
  /**
   * 1. Autentikasi Pengguna & Pengecekan Device Awal
   * Kredensial valid + Device ID terdaftar
   */
  static loginUser(username, password, deviceId) {
    if (!username || !password) {
      return { success: false, status: 400, message: 'Username dan password wajib diisi.' };
    }

    if (!deviceId) {
      return { success: false, status: 400, message: 'Header X-Device-ID wajib disertakan saat login.' };
    }

    // Cari user
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
      this.logAudit({
        subject: username,
        endpoint: '/auth/login',
        method: 'POST',
        deviceId,
        decision: 'DENY',
        reason: 'User tidak ditemukan'
      });
      return { success: false, status: 401, message: 'Kredensial tidak valid.' };
    }

    // Verifikasi password
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      this.logAudit({
        subject: username,
        endpoint: '/auth/login',
        method: 'POST',
        deviceId,
        decision: 'DENY',
        reason: 'Password salah'
      });
      return { success: false, status: 401, message: 'Kredensial tidak valid.' };
    }

    // Verifikasi Device Terdaftar (Zero Trust Context Check)
    const device = db.prepare(`
      SELECT * FROM devices 
      WHERE user_id = ? AND device_id = ? AND is_active = 1
    `).get(user.id, deviceId);

    if (!device) {
      this.logAudit({
        subject: user.username,
        endpoint: '/auth/login',
        method: 'POST',
        deviceId,
        decision: 'DENY',
        reason: `Device ${deviceId} tidak terdaftar untuk pengguna ${user.username}`
      });
      return { 
        success: false, 
        status: 403, 
        message: `Akses ditolak: Device ${deviceId} tidak terdaftar untuk pengguna ini.` 
      };
    }

    // Terbitkan Access Token (10 menit)
    const payload = {
      sub: user.id,
      username: user.username,
      nama: user.nama,
      role: user.role,
      nim: user.nim,
      nidn: user.nidn
    };

    const accessToken = jwt.sign(payload, config.JWT_SECRET, {
      expiresIn: config.ACCESS_TOKEN_EXPIRY
    });

    // Terbitkan Refresh Token (1 hari) & Simpan di Database
    const refreshToken = crypto.randomBytes(40).toString('hex');
    const expiresAt = new Date(Date.now() + config.REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000).toISOString();

    db.prepare(`
      INSERT INTO refresh_tokens (user_id, token, expires_at, is_revoked)
      VALUES (?, ?, ?, 0)
    `).run(user.id, refreshToken, expiresAt);

    this.logAudit({
      subject: user.username,
      endpoint: '/auth/login',
      method: 'POST',
      deviceId,
      decision: 'ALLOW',
      reason: 'Login berhasil dengan kredensial dan device valid'
    });

    return {
      success: true,
      status: 200,
      data: {
        message: 'Login berhasil.',
        user: {
          id: user.id,
          username: user.username,
          nama: user.nama,
          role: user.role,
          nim: user.nim,
          nidn: user.nidn
        },
        device: {
          deviceId: device.device_id,
          deviceName: device.device_name
        },
        accessToken,
        refreshToken,
        expiresIn: config.ACCESS_TOKEN_EXPIRY
      }
    };
  }

  /**
   * 2. Refresh Token
   */
  static refreshToken(token, deviceId) {
    if (!token) {
      return { success: false, status: 400, message: 'Refresh token wajib disertakan.' };
    }

    const tokenRecord = db.prepare(`
      SELECT rt.*, u.username, u.nama, u.role, u.nim, u.nidn 
      FROM refresh_tokens rt
      JOIN users u ON rt.user_id = u.id
      WHERE rt.token = ?
    `).get(token);

    if (!tokenRecord) {
      this.logAudit({
        subject: 'anonymous',
        endpoint: '/auth/refresh',
        method: 'POST',
        deviceId,
        decision: 'DENY',
        reason: 'Refresh token tidak ditemukan'
      });
      return { success: false, status: 401, message: 'Refresh token tidak valid.' };
    }

    if (tokenRecord.is_revoked === 1) {
      this.logAudit({
        subject: tokenRecord.username,
        endpoint: '/auth/refresh',
        method: 'POST',
        deviceId,
        decision: 'DENY',
        reason: 'Refresh token telah dicabut (revoked)'
      });
      return { success: false, status: 403, message: 'Refresh token telah dicabut.' };
    }

    if (new Date(tokenRecord.expires_at) < new Date()) {
      this.logAudit({
        subject: tokenRecord.username,
        endpoint: '/auth/refresh',
        method: 'POST',
        deviceId,
        decision: 'DENY',
        reason: 'Refresh token telah kedaluwarsa'
      });
      return { success: false, status: 403, message: 'Refresh token telah kedaluwarsa.' };
    }

    // Terbitkan Access Token baru
    const payload = {
      sub: tokenRecord.user_id,
      username: tokenRecord.username,
      nama: tokenRecord.nama,
      role: tokenRecord.role,
      nim: tokenRecord.nim,
      nidn: tokenRecord.nidn
    };

    const newAccessToken = jwt.sign(payload, config.JWT_SECRET, {
      expiresIn: config.ACCESS_TOKEN_EXPIRY
    });

    this.logAudit({
      subject: tokenRecord.username,
      endpoint: '/auth/refresh',
      method: 'POST',
      deviceId,
      decision: 'ALLOW',
      reason: 'Refresh access token berhasil'
    });

    return {
      success: true,
      status: 200,
      data: {
        accessToken: newAccessToken,
        expiresIn: config.ACCESS_TOKEN_EXPIRY
      }
    };
  }

  /**
   * 3. Logout (Pencabutan Refresh Token)
   */
  static logout(token, deviceId) {
    if (!token) {
      return { success: false, status: 400, message: 'Refresh token wajib disertakan untuk logout.' };
    }

    const tokenRecord = db.prepare(`
      SELECT rt.*, u.username FROM refresh_tokens rt
      JOIN users u ON rt.user_id = u.id
      WHERE rt.token = ?
    `).get(token);

    if (!tokenRecord) {
      return { success: false, status: 404, message: 'Refresh token tidak ditemukan.' };
    }

    db.prepare('UPDATE refresh_tokens SET is_revoked = 1 WHERE token = ?').run(token);

    this.logAudit({
      subject: tokenRecord.username,
      endpoint: '/auth/logout',
      method: 'POST',
      deviceId,
      decision: 'ALLOW',
      reason: 'Logout berhasil, refresh token dicabut'
    });

    return { success: true, status: 200, message: 'Logout berhasil. Token telah dicabut.' };
  }

  /**
   * 4. Token Service (M2M Auth: Service Nilai -> Gateway)
   */
  static authenticateService(clientId, clientSecret) {
    const registered = config.SERVICE_CLIENTS[clientId];
    if (!registered || registered.secret !== clientSecret) {
      this.logAudit({
        subject: clientId || 'unknown-service',
        endpoint: '/auth/service',
        method: 'POST',
        deviceId: 'INTERNAL-SERVICE-BUS',
        decision: 'DENY',
        reason: 'Service Client ID atau Secret tidak valid'
      });
      return { success: false, status: 401, message: 'Kredensial service tidak valid.' };
    }

    const payload = {
      sub: clientId,
      name: registered.name,
      role: 'service'
    };

    const serviceToken = jwt.sign(payload, config.JWT_SECRET, {
      expiresIn: config.SERVICE_TOKEN_EXPIRY
    });

    this.logAudit({
      subject: clientId,
      endpoint: '/auth/service',
      method: 'POST',
      deviceId: 'INTERNAL-SERVICE-BUS',
      decision: 'ALLOW',
      reason: 'Service token berhasil diterbitkan'
    });

    return {
      success: true,
      status: 200,
      data: {
        serviceToken,
        expiresIn: config.SERVICE_TOKEN_EXPIRY,
        role: 'service'
      }
    };
  }

  /**
   * 5. Policy Decision Engine (PEP asks PE / PA)
   * Menilai: Subjek, Token, Device Context, Jam Akses, & Kepemilikan Data
   */
  static evaluateAccess({ method, path, headers, params, body }) {
    const authHeader = headers['authorization'];
    const deviceId = headers['x-device-id'];

    // 1. Verifikasi Keberadaan Authorization Header
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        allow: false,
        status: 401,
        reason: 'Header Authorization Bearer token wajib disertakan'
      };
    }

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
      decoded = jwt.verify(token, config.JWT_SECRET);
    } catch (err) {
      return {
        allow: false,
        status: 401,
        reason: `Token tidak valid atau kedaluwarsa: ${err.message}`
      };
    }

    const subject = decoded.username || decoded.sub;
    const role = decoded.role;

    // 2. Verifikasi Konteks: Device Terdaftar (Wajib untuk request Pengguna)
    if (role !== 'service') {
      if (!deviceId) {
        return {
          allow: false,
          status: 403,
          subject,
          reason: 'Header X-Device-ID wajib disertakan untuk semua akses pengguna'
        };
      }

      const device = db.prepare(`
        SELECT * FROM devices 
        WHERE user_id = ? AND device_id = ? AND is_active = 1
      `).get(decoded.sub, deviceId);

      if (!device) {
        return {
          allow: false,
          status: 403,
          subject,
          reason: `Device ${deviceId} tidak terdaftar untuk pengguna ${subject}`
        };
      }
    }

    // 3. Verifikasi Konteks: Jam Akses (07.00 - 21.00)
    // Berlaku untuk operasi perubahan/finalisasi nilai: PUT /nilai/:id dan POST /kelas/:id/finalisasi
    const isMutationRoute = 
      (method === 'PUT' && path.startsWith('/nilai/')) ||
      (method === 'POST' && path.includes('/finalisasi'));

    if (isMutationRoute) {
      const currentHour = new Date().getHours();
      const { start, end } = config.ACCESS_HOURS;
      if (currentHour < start || currentHour >= end) {
        return {
          allow: false,
          status: 403,
          subject,
          reason: `Akses ditolak: Perubahan atau finalisasi nilai hanya diizinkan pukul ${String(start).padStart(2, '0')}.00 - ${String(end).padStart(2, '0')}.00 WIB (Waktu sekarang: jam ${currentHour})`
        };
      }
    }

    // 4. Evaluasi Kebijakan Akses Berdasarkan Tabel 3 Spesifikasi

    // === ROUTE: GET /nilai ===
    if (method === 'GET' && (path === '/nilai' || path === '/nilai/')) {
      if (role !== 'mahasiswa' && role !== 'dosen') {
        return {
          allow: false,
          status: 403,
          subject,
          reason: 'Hanya Mahasiswa dan Dosen yang diizinkan mengakses data nilai'
        };
      }
      return {
        allow: true,
        subject,
        user: decoded,
        reason: `Akses diizinkan untuk role ${role}`
      };
    }

    // === ROUTE: PUT /nilai/:id ===
    const nilaiMatch = path.match(/^\/nilai\/(\d+)$/);
    if (method === 'PUT' && nilaiMatch) {
      const nilaiId = parseInt(nilaiMatch[1], 10);

      if (role !== 'dosen') {
        return {
          allow: false,
          status: 403,
          subject,
          reason: 'Hanya Dosen yang diizinkan mengubah nilai'
        };
      }

      // Periksa kepemilikan data dari database
      const record = db.prepare(`
        SELECT n.id, n.is_final AS nilai_is_final, k.is_final AS kelas_is_final, k.dosen_id, k.nama_mk
        FROM nilai n
        JOIN kelas k ON n.kelas_id = k.id
        WHERE n.id = ?
      `).get(nilaiId);

      if (!record) {
        return {
          allow: false,
          status: 404,
          subject,
          reason: `Data nilai dengan ID ${nilaiId} tidak ditemukan`
        };
      }

      if (record.dosen_id !== decoded.sub) {
        return {
          allow: false,
          status: 403,
          subject,
          reason: `Dosen ${subject} bukan pengampu kelas untuk nilai mata kuliah ${record.nama_mk}`
        };
      }

      if (record.nilai_is_final === 1 || record.kelas_is_final === 1) {
        return {
          allow: false,
          status: 403,
          subject,
          reason: `Nilai ID ${nilaiId} telah difinalisasi dan tidak dapat diubah lagi`
        };
      }

      return {
        allow: true,
        subject,
        user: decoded,
        reason: `Dosen pengampu valid dan nilai belum final`
      };
    }

    // === ROUTE: POST /kelas/:id/finalisasi ===
    const finalisasiMatch = path.match(/^\/kelas\/(\d+)\/finalisasi$/);
    if (method === 'POST' && finalisasiMatch) {
      const kelasId = parseInt(finalisasiMatch[1], 10);

      if (role !== 'dosen') {
        return {
          allow: false,
          status: 403,
          subject,
          reason: 'Hanya Dosen yang diizinkan memfinalisasi kelas'
        };
      }

      const kelasRecord = db.prepare(`
        SELECT id, nama_mk, dosen_id, is_final FROM kelas WHERE id = ?
      `).get(kelasId);

      if (!kelasRecord) {
        return {
          allow: false,
          status: 404,
          subject,
          reason: `Kelas dengan ID ${kelasId} tidak ditemukan`
        };
      }

      if (kelasRecord.dosen_id !== decoded.sub) {
        return {
          allow: false,
          status: 403,
          subject,
          reason: `Dosen ${subject} bukan pengampu kelas ${kelasRecord.nama_mk}`
        };
      }

      if (kelasRecord.is_final === 1) {
        return {
          allow: false,
          status: 400,
          subject,
          reason: `Kelas ${kelasRecord.nama_mk} sudah pernah difinalisasi sebelumnya`
        };
      }

      return {
        allow: true,
        subject,
        user: decoded,
        reason: `Dosen pengampu valid untuk finalisasi kelas ${kelasRecord.nama_mk}`
      };
    }

    // === ROUTE: GET /transkrip/:nim ===
    const transkripMatch = path.match(/^\/transkrip\/([a-zA-Z0-9]+)$/);
    if (method === 'GET' && transkripMatch) {
      const requestedNim = transkripMatch[1];

      if (role === 'admin') {
        return {
          allow: true,
          subject,
          user: decoded,
          reason: `Admin berhak melihat transkrip seluruh mahasiswa`
        };
      }

      if (role === 'mahasiswa') {
        if (decoded.nim !== requestedNim) {
          return {
            allow: false,
            status: 403,
            subject,
            reason: `Mahasiswa ${subject} (NIM: ${decoded.nim}) dilarang melihat transkrip NIM lain (${requestedNim})`
          };
        }
        return {
          allow: true,
          subject,
          user: decoded,
          reason: `Mahasiswa melihat transkrip miliknya sendiri (NIM: ${requestedNim})`
        };
      }

      return {
        allow: false,
        status: 403,
        subject,
        reason: `Role ${role} tidak memiliki hak akses melihat transkrip`
      };
    }

    // === ROUTE: POST /transkrip/sinkron ===
    if (method === 'POST' && (path === '/transkrip/sinkron' || path === '/transkrip/sinkron/')) {
      if (role !== 'service') {
        return {
          allow: false,
          status: 403,
          subject,
          reason: `Akses ditolak: Endpoint sinkronisasi transkrip HANYA menerima token service (M2M). Token pengguna dengan role '${role}' ditolak.`
        };
      }

      return {
        allow: true,
        subject,
        user: decoded,
        reason: `Token service valid untuk sinkronisasi transkrip`
      };
    }

    // Rute tidak dikenal
    return {
      allow: false,
      status: 404,
      subject,
      reason: `Endpoint ${method} ${path} tidak didefinisikan dalam kebijakan akses`
    };
  }

  /**
   * 6. Audit Logging (NIST SP 800-207 Policy Decision Telemetry)
   */
  static logAudit({ subject, endpoint, method, deviceId, decision, reason }) {
    try {
      db.prepare(`
        INSERT INTO audit_logs (timestamp, subject, endpoint, method, device_id, decision, reason)
        VALUES (datetime('now', 'localtime'), ?, ?, ?, ?, ?, ?)
      `).run(
        subject || 'anonymous',
        endpoint,
        method,
        deviceId || null,
        decision,
        reason
      );
      const color = decision === 'ALLOW' ? '\x1b[32m[ALLOW]\x1b[0m' : '\x1b[31m[DENY]\x1b[0m';
      console.log(`[AUDIT LOG] ${color} ${method} ${endpoint} | Sub: ${subject} | Dev: ${deviceId || '-'} | Alasan: ${reason}`);
    } catch (err) {
      console.error('Gagal menulis audit log:', err.message);
    }
  }
}

module.exports = PolicyEngine;
