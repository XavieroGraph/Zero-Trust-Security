const express = require('express');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');
const config = require('../config');
const db = require('../db/db');
const PolicyEngine = require('./policy');

const app = express();

// Body Parser untuk request JSON
app.use(express.json());

// Banner Konsol Zero Trust
console.log('================================================================');
console.log('  ZERO TRUST SECURITY API GATEWAY (POLICY ENFORCEMENT POINT)');
console.log('  Mata Kuliah: Keamanan Informasi - Universitas Siliwangi');
console.log(`  Gateway Secret: ${config.GATEWAY_SECRET.substring(0, 15)}...`);
console.log(`  Jam Akses Nilai: ${config.ACCESS_HOURS.start}:00 - ${config.ACCESS_HOURS.end}:00 WIB`);
console.log('================================================================');

// =============================================================================
// 1. ENDPOINTS AUTENTIKASI & TOKEN (/auth/*) - Ditangani Langsung oleh Gateway
// =============================================================================

/**
 * POST /auth/login
 * Input: { username, password }
 * Header wajib: X-Device-ID
 */
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  const deviceId = req.headers['x-device-id'];

  const result = PolicyEngine.loginUser(username, password, deviceId);
  return res.status(result.status).json(result.data || { error: result.message });
});

/**
 * POST /auth/refresh
 * Input: { refreshToken }
 * Header wajib: X-Device-ID
 */
app.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;
  const deviceId = req.headers['x-device-id'];

  const result = PolicyEngine.refreshToken(refreshToken, deviceId);
  return res.status(result.status).json(result.data || { error: result.message });
});

/**
 * POST /auth/logout
 * Input: { refreshToken }
 * Header wajib: X-Device-ID
 */
app.post('/auth/logout', (req, res) => {
  const { refreshToken } = req.body;
  const deviceId = req.headers['x-device-id'];

  const result = PolicyEngine.logout(refreshToken, deviceId);
  return res.status(result.status).json(result);
});

/**
 * POST /auth/service
 * Input: { clientId, clientSecret }
 * Khusus Service Nilai untuk otentikasi Machine-to-Machine (M2M)
 */
app.post('/auth/service', (req, res) => {
  const { clientId, clientSecret } = req.body;

  const result = PolicyEngine.authenticateService(clientId, clientSecret);
  return res.status(result.status).json(result.data || { error: result.message });
});

/**
 * GET /audit-logs
 * Endpoint telemetri monitoring untuk memverifikasi seluruh keputusan PEP
 */
app.get('/audit-logs', (req, res) => {
  try {
    const limit = parseInt(req.query.limit || '50', 10);
    const logs = db.prepare(`
      SELECT * FROM audit_logs 
      ORDER BY id DESC 
      LIMIT ?
    `).all(limit);

    return res.json({
      success: true,
      total: logs.length,
      logs
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// =============================================================================
// 2. POLICY ENFORCEMENT POINT (PEP) MIDDLEWARE
// Memeriksa setiap request sebelum diteruskan ke Resource Services
// =============================================================================

function pepMiddleware(req, res, next) {
  const urlPath = req.originalUrl.split('?')[0];

  const decision = PolicyEngine.evaluateAccess({
    method: req.method,
    path: urlPath,
    headers: req.headers,
    params: req.params,
    body: req.body
  });

  // Catat keputusan ke Audit Log (NIST SP 800-207 telemetry)
  PolicyEngine.logAudit({
    subject: decision.subject || 'anonymous',
    endpoint: req.originalUrl,
    method: req.method,
    deviceId: req.headers['x-device-id'] || null,
    decision: decision.allow ? 'ALLOW' : 'DENY',
    reason: decision.reason
  });

  if (!decision.allow) {
    return res.status(decision.status || 403).json({
      success: false,
      error: 'PEP Policy Denied',
      status: decision.status || 403,
      reason: decision.reason
    });
  }

  // Jika ALLOW, simpan subjek terverifikasi dan lanjutkan ke proxy
  req.verifiedUser = decision.user;
  next();
}

// =============================================================================
// 3. PROXY KE RESOURCE SERVICES DENGAN INJEKSI X-Gateway-Secret
// =============================================================================

// Helper konfigurasi proxy request
function onProxyReqHandler(proxyReq, req, res) {
  // Injeksi X-Gateway-Secret yang membuktikan request telah lolos dari PEP Gateway
  proxyReq.setHeader('X-Gateway-Secret', config.GATEWAY_SECRET);

  // Re-stream request body jika sebelumnya telah diparse oleh express.json()
  fixRequestBody(proxyReq, req);
}

// Proxy untuk Service Nilai (Port 3001) - Mengelola /nilai dan /kelas
const nilaiProxy = createProxyMiddleware({
  target: `http://localhost:${config.PORT_NILAI}`,
  changeOrigin: true,
  pathRewrite: (path, req) => req.originalUrl,
  on: {
    proxyReq: onProxyReqHandler
  },
  onProxyReq: onProxyReqHandler // Kompatibilitas cross-version
});

// Proxy untuk Service Transkrip (Port 3002) - Mengelola /transkrip
const transkripProxy = createProxyMiddleware({
  target: `http://localhost:${config.PORT_TRANSKRIP}`,
  changeOrigin: true,
  pathRewrite: (path, req) => req.originalUrl,
  on: {
    proxyReq: onProxyReqHandler
  },
  onProxyReq: onProxyReqHandler
});

// Pemasangan rute Resource terproteksi dengan PEP
app.use(['/nilai', '/kelas'], pepMiddleware, nilaiProxy);
app.use('/transkrip', pepMiddleware, transkripProxy);

// 404 Handler untuk route lainnya
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not Found',
    message: `Endpoint ${req.method} ${req.originalUrl} tidak ditemukan pada API Gateway.`
  });
});

// Jalankan Gateway di Port 3000
const server = app.listen(config.PORT_GATEWAY, () => {
  console.log(`✔ [API Gateway (PEP)] Berjalan di port ${config.PORT_GATEWAY}`);
});

module.exports = { app, server };
