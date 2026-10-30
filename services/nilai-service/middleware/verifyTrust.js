const jwt = require('jsonwebtoken');
const config = require('../../../config');

/**
 * Middleware Verifikasi Keamanan Zero Trust untuk Microservices
 * Menerapkan prinsip: Assume Breach & Never Trust, Always Verify.
 * 1. Memeriksa keberadaan dan kecocokan X-Gateway-Secret.
 * 2. Memverifikasi ulang keaslian dan masa berlaku JWT Token secara mandiri.
 */
function verifyTrust(req, res, next) {
  // 1. Verifikasi Header Gateway Secret
  const gatewaySecret = req.headers['x-gateway-secret'];
  if (!gatewaySecret || gatewaySecret !== config.GATEWAY_SECRET) {
    return res.status(403).json({
      success: false,
      error: 'Direct Access Denied (Zero Trust Violation)',
      message: 'Akses langsung ke internal microservice dilarang. Seluruh request wajib melalui API Gateway (PEP) yang sah.'
    });
  }

  // 2. Verifikasi Ulang Tanda Tangan & Masa Berlaku JWT
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'Missing Authorization Token',
      message: 'Token otentikasi Bearer wajib disertakan pada request.'
    });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, config.JWT_SECRET);
    req.user = decoded; // Menyimpan konteks subjek terverifikasi ke dalam request
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or Expired Token',
      message: `Verifikasi ulang token di service gagal: ${err.message}`
    });
  }
}

module.exports = verifyTrust;
