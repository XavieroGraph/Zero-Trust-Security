const path = require('path');

module.exports = {
  // Ports
  PORT_GATEWAY: process.env.PORT_GATEWAY || 3000,
  PORT_NILAI: process.env.PORT_NILAI || 3001,
  PORT_TRANSKRIP: process.env.PORT_TRANSKRIP || 3002,

  // Secrets
  JWT_SECRET: process.env.JWT_SECRET || 'zero-trust-super-secret-jwt-key-unsil-2024',
  GATEWAY_SECRET: process.env.GATEWAY_SECRET || 'X-PEP-GATEWAY-INTERNAL-SECRET-AUTHENTICITY-KEY',

  // Service Auth Credentials (Service Nilai -> Gateway)
  SERVICE_CLIENTS: {
    'service-nilai': {
      secret: 'nilai-service-credential-2024',
      name: 'Service Nilai Internal'
    }
  },

  // Token Lifespans
  ACCESS_TOKEN_EXPIRY: '10m',
  REFRESH_TOKEN_DAYS: 1,
  SERVICE_TOKEN_EXPIRY: '5m',

  // Context: Working Hours for Grade modifications (07:00 - 21:00 default)
  // Bisa diubah melalui env ACCESS_START_HOUR dan ACCESS_END_HOUR untuk kemudahan demo
  ACCESS_HOURS: {
    start: parseInt(process.env.ACCESS_START_HOUR ?? '7', 10),
    end: parseInt(process.env.ACCESS_END_HOUR ?? '21', 10)
  },

  // Database Path
  DB_PATH: path.join(__dirname, 'db', 'database.sqlite')
};
