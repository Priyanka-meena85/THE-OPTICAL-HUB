/**
 * THE OPTICAL HUB — Secure Database Layer
 * Built with parameterized queries to eliminate SQL Injection (Checklist #1)
 * Enforces Row-Level Security (RLS) & IDOR Protection (Checklist #6, #12)
 */

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const DB_PATH = path.join(__dirname, 'optical_hub.db');
const db = new DatabaseSync(DB_PATH);

// Initialize Tables
db.exec(`
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'patient',
    mfa_secret TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS prescriptions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    patient_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    sphere_r TEXT DEFAULT '0.00',
    sphere_l TEXT DEFAULT '0.00',
    cyl_r TEXT DEFAULT '0.00',
    cyl_l TEXT DEFAULT '0.00',
    axis_r TEXT DEFAULT '0',
    axis_l TEXT DEFAULT '0',
    add_power TEXT DEFAULT '+0.00',
    notes TEXT,
    file_path TEXT,
    file_hash TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS appointments (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    age INTEGER NOT NULL,
    date TEXT NOT NULL,
    slot TEXT NOT NULL,
    home_test INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'confirmed',
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS repairs (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    problem TEXT NOT NULL,
    date TEXT NOT NULL,
    photo_path TEXT,
    status TEXT NOT NULL DEFAULT 'Raised',
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS ai_night_calls (
    id TEXT PRIMARY KEY,
    caller_phone TEXT,
    transcript TEXT NOT NULL,
    intent TEXT NOT NULL,
    summary TEXT,
    audio_requested INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    user_id TEXT,
    ip_address TEXT,
    details TEXT,
    created_at TEXT NOT NULL
  );
`);

// Password hashing utility using scrypt with cryptographically secure salts (Checklist #8)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}

function verifyPassword(password, hash, salt) {
  const checkHash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(checkHash, 'hex'));
}

// Seed default admin account with strong password if not present (Checklist #16)
const checkAdmin = db.prepare('SELECT id FROM users WHERE role = ?').get('admin');
if (!checkAdmin) {
  const adminId = 'admin_' + crypto.randomUUID().slice(0, 8);
  const secureAdminPass = process.env.ADMIN_INITIAL_PASSWORD || 'OpticalHub#Jaipur2026';
  const { hash, salt } = hashPassword(secureAdminPass);
  
  db.prepare(`
    INSERT INTO users (id, name, phone, password_hash, salt, role, mfa_enabled, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
  `).run(adminId, 'Ramesh Sharma (Admin)', '9509959157', hash, salt, 'admin', new Date().toISOString());
  
  console.log('[Security Audit] Initialized verified staff admin account (Ramesh Sharma)');
}

// ----------------------------------------------------
// Parameterized Database Methods (SQL Injection Safe)
// ----------------------------------------------------

const database = {
  // Users
  createUser: ({ name, phone, password, role = 'patient' }) => {
    const id = 'usr_' + crypto.randomUUID();
    const { hash, salt } = hashPassword(password);
    const now = new Date().toISOString();
    
    db.prepare(`
      INSERT INTO users (id, name, phone, password_hash, salt, role, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, name, phone, hash, salt, role, now);
    
    return { id, name, phone, role };
  },

  getUserByPhone: (phone) => {
    return db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  },

  getUserById: (id) => {
    return db.prepare('SELECT id, name, phone, role, mfa_enabled, created_at FROM users WHERE id = ?').get(id);
  },

  enableMfa: (userId, secret) => {
    return db.prepare('UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?').run(secret, userId);
  },

  // Prescriptions with RLS (Row Level Security & IDOR Protection - Checklist #6, #12)
  createPrescription: (data) => {
    const id = 'rx_' + crypto.randomUUID();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO prescriptions (id, user_id, patient_name, phone, sphere_r, sphere_l, cyl_r, cyl_l, axis_r, axis_l, add_power, notes, file_path, file_hash, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id, data.userId, data.patientName, data.phone,
      data.sphereR || '0.00', data.sphereL || '0.00',
      data.cylR || '0.00', data.cylL || '0.00',
      data.axisR || '0', data.axisL || '0',
      data.addPower || '+0.00', data.notes || '',
      data.filePath || null, data.fileHash || null, now
    );
    return { id, ...data, created_at: now };
  },

  getPrescriptionsByUser: (userId, isStaff = false) => {
    // If staff/admin, can view clinic prescriptions; if patient, STRICTLY scoped to their own userId (RLS / BOLA prevention)
    if (isStaff) {
      return db.prepare('SELECT * FROM prescriptions ORDER BY created_at DESC').all();
    }
    return db.prepare('SELECT * FROM prescriptions WHERE user_id = ? ORDER BY created_at DESC').all(userId);
  },

  getPrescriptionById: (id, userId, isStaff = false) => {
    const rx = db.prepare('SELECT * FROM prescriptions WHERE id = ?').get(id);
    if (!rx) return null;
    // BOLA/IDOR Check: reject if requested by another patient
    if (!isStaff && rx.user_id !== userId) {
      throw new Error('ACCESS_DENIED_BOLA_VIOLATION');
    }
    return rx;
  },

  // Appointments (Eye Test)
  createAppointment: (data) => {
    const id = 'apt_' + crypto.randomUUID();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO appointments (id, user_id, name, phone, age, date, slot, home_test, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'confirmed', ?)
    `).run(id, data.userId || null, data.name, data.phone, data.age, data.date, data.slot, data.homeTest ? 1 : 0, now);
    return { id, ...data, status: 'confirmed', created_at: now };
  },

  getAppointmentsByUser: (userId, isStaff = false, phone = null) => {
    if (isStaff) {
      return db.prepare('SELECT * FROM appointments ORDER BY date DESC, slot ASC').all();
    }
    if (userId) {
      return db.prepare('SELECT * FROM appointments WHERE user_id = ? OR phone = ? ORDER BY date DESC').all(userId, phone || '');
    }
    if (phone) {
      return db.prepare('SELECT * FROM appointments WHERE phone = ? ORDER BY date DESC').all(phone);
    }
    return [];
  },

  // Repairs
  createRepair: (data) => {
    const id = 'rep_' + crypto.randomUUID();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO repairs (id, user_id, name, phone, problem, date, photo_path, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'Raised', ?)
    `).run(id, data.userId || null, data.name, data.phone, data.problem, data.date, data.photoPath || null, now);
    return { id, ...data, status: 'Raised', created_at: now };
  },

  getRepairsByUser: (userId, isStaff = false, phone = null) => {
    if (isStaff) {
      return db.prepare('SELECT * FROM repairs ORDER BY created_at DESC').all();
    }
    if (userId) {
      return db.prepare('SELECT * FROM repairs WHERE user_id = ? OR phone = ? ORDER BY created_at DESC').all(userId, phone || '');
    }
    if (phone) {
      return db.prepare('SELECT * FROM repairs WHERE phone = ? ORDER BY created_at DESC').all(phone);
    }
    return [];
  },

  updateRepairStatus: (repairId, newStatus) => {
    return db.prepare('UPDATE repairs SET status = ? WHERE id = ?').run(newStatus, repairId);
  },

  // AI Night Call Records
  logAiNightCall: (data) => {
    const id = 'call_' + crypto.randomUUID();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO ai_night_calls (id, caller_phone, transcript, intent, summary, audio_requested, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, data.callerPhone || 'Anonymous', data.transcript, data.intent, data.summary, data.audioRequested ? 1 : 0, now);
    return { id, ...data, created_at: now };
  },

  getAiNightCalls: () => {
    return db.prepare('SELECT * FROM ai_night_calls ORDER BY created_at DESC LIMIT 50').all();
  },

  // Audit Log (Security compliance)
  logSecurityEvent: (eventType, userId, ip, details) => {
    const id = 'aud_' + crypto.randomUUID();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO audit_logs (id, event_type, user_id, ip_address, details, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, eventType, userId || null, ip || '127.0.0.1', JSON.stringify(details || {}), now);
  },

  getRecentAuditLogs: () => {
    return db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 25').all();
  },

  verifyPassword
};

module.exports = database;
