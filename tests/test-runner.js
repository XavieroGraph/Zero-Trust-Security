const { server: serverGateway } = require('../gateway/gateway');
const { server: serverNilai } = require('../services/nilai-service/server');
const { server: serverTranskrip } = require('../services/transkrip-service/server');
const runTests = require('./test-scenarios');

async function main() {
  console.log('Menunggu seluruh service aktif...');
  await new Promise((r) => setTimeout(r, 1000));

  try {
    await runTests();
  } catch (err) {
    console.error('Pengujian gagal dengan error tak tertangani:', err);
  } finally {
    console.log('Menutup server pengujian...');
    serverGateway.close();
    serverNilai.close();
    serverTranskrip.close();
    process.exit(0);
  }
}

main();
