/**
 * THE OPTICAL HUB — Secure Redacting Logger
 * Checklist #19: Sensitive Logs production me mat rakho
 * 
 * Automatically redacts PII, passwords, credit card numbers, and patient prescription data.
 */

const SENSITIVE_KEYS = [
  'password',
  'password_hash',
  'token',
  'auth_token',
  'jwt',
  'secret',
  'mfa_secret',
  'cardNumber',
  'cvv',
  'prescription',
  'sphere_r',
  'cyl_r'
];

function redactData(obj, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 5) return obj;

  if (Array.isArray(obj)) {
    return obj.map(item => redactData(item, depth + 1));
  }

  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    const isSensitive = SENSITIVE_KEYS.some(k => key.toLowerCase().includes(k.toLowerCase()));
    if (isSensitive) {
      sanitized[key] = '[REDACTED_SENSITIVE_DATA]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = redactData(value, depth + 1);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

const secureLogger = {
  info: (message, meta = {}) => {
    console.log(`[INFO] ${new Date().toISOString()} - ${message}`, redactData(meta));
  },
  warn: (message, meta = {}) => {
    console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, redactData(meta));
  },
  error: (message, meta = {}) => {
    console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, redactData(meta));
  },
  audit: (action, meta = {}) => {
    console.log(`[AUDIT_TRAIL] ${new Date().toISOString()} - Action: ${action}`, redactData(meta));
  }
};

module.exports = secureLogger;
