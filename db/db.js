const path = require('path');
const fs = require('fs');
const config = require('../config');

// Pastikan direktori db ada
const dbDir = path.dirname(config.DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

let dbInstance;
const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);

if (nodeMajor >= 24) {
  // Node.js 24+ menyediakan engine bawaan node:sqlite dengan API DatabaseSync sinkron
  // Menghindari issue Assertion failed pada C++ cleanup hook native better-sqlite3 di Node 24
  const { DatabaseSync } = require('node:sqlite');
  const rawDb = new DatabaseSync(config.DB_PATH);
  rawDb.exec('PRAGMA foreign_keys = ON;');
  rawDb.exec('PRAGMA journal_mode = WAL;');

  dbInstance = {
    prepare(sql) {
      const stmt = rawDb.prepare(sql);
      return {
        run(...params) {
          const res = stmt.run(...params);
          return {
            changes: res.changes,
            lastInsertRowid: Number(res.lastInsertRowid)
          };
        },
        get(...params) {
          return stmt.get(...params);
        },
        all(...params) {
          return stmt.all(...params);
        }
      };
    },
    exec(sql) {
      return rawDb.exec(sql);
    },
    pragma(sql) {
      return rawDb.exec(`PRAGMA ${sql};`);
    },
    close() {
      return rawDb.close();
    }
  };
} else {
  // Untuk Node.js <= 22 LTS (Node 18, 20, 22) menggunakan better-sqlite3 sesuai spesifikasi
  const Database = require('better-sqlite3');
  const rawDb = new Database(config.DB_PATH);
  rawDb.pragma('foreign_keys = ON');
  rawDb.pragma('journal_mode = WAL');
  dbInstance = rawDb;
}

module.exports = dbInstance;
