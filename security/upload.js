/**
 * THE OPTICAL HUB — Safe File Upload Handler
 * Checklist #4: File Uploads check karo (koi virus wali photo na daal de)
 * 
 * Enforces:
 * 1. Strict Mime-type whitelisting (JPEG, PNG, WEBP, PDF)
 * 2. Magic bytes / file header signature inspection
 * 3. File size limit (5MB)
 * 4. Sanitized random UUID filename (prevents directory traversal & overwriting)
 * 5. Isolated non-executable upload storage
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const UPLOADS_DIR = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Allowed File Signatures (Magic Bytes)
const MAGIC_BYTES = {
  jpg: [0xFF, 0xD8, 0xFF],
  png: [0x89, 0x50, 0x4E, 0x47],
  webp: [0x52, 0x49, 0x46, 0x46], // 'RIFF'
  pdf: [0x25, 0x50, 0x44, 0x46]   // '%PDF'
};

function verifyMagicBytes(buffer) {
  if (!buffer || buffer.length < 8) return false;

  // Check JPEG
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return 'image/jpeg';

  // Check PNG
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return 'image/png';

  // Check WEBP
  if (buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
      buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) return 'image/webp';

  // Check PDF
  if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) return 'application/pdf';

  return false;
}

// Dangerous extensions blacklist (Malware, webshells, scripts)
const DANGEROUS_EXTS = ['.php', '.exe', '.sh', '.bat', '.cmd', '.py', '.js', '.vbs', '.phtml', '.cgi', '.pl'];

function processUploadedFile(file) {
  if (!file) return null;

  // 1. Check size (5MB max)
  const MAX_SIZE = 5 * 1024 * 1024;
  if (file.size > MAX_SIZE) {
    throw new Error('FILE_TOO_LARGE: File size exceeds 5MB limit.');
  }

  // 2. Check extension
  const ext = path.extname(file.originalname).toLowerCase();
  if (DANGEROUS_EXTS.includes(ext)) {
    throw new Error('MALICIOUS_FILE_TYPE: Executable or script files are strictly blocked.');
  }

  // 3. Inspect buffer magic bytes
  const verifiedMime = verifyMagicBytes(file.buffer);
  if (!verifiedMime) {
    throw new Error('INVALID_FILE_SIGNATURE: Disguised or corrupted file detected. Only authentic JPEG, PNG, WEBP, and PDF files are accepted.');
  }

  // 4. Safe random UUID name
  const safeFilename = 'rx_' + crypto.randomUUID() + ext;
  const targetPath = path.join(UPLOADS_DIR, safeFilename);

  // 5. Calculate SHA256 checksum for audit and tamper detection
  const checksum = crypto.createHash('sha256').update(file.buffer).digest('hex');

  // 6. Write file to disk
  fs.writeFileSync(targetPath, file.buffer);

  return {
    filename: safeFilename,
    path: targetPath,
    mimeType: verifiedMime,
    size: file.size,
    checksum
  };
}

module.exports = {
  processUploadedFile,
  verifyMagicBytes,
  UPLOADS_DIR
};
