/**
 * THE OPTICAL HUB — CSRF Protection Middleware
 * Checklist #3: CSRF Lagao
 * 
 * Implements double-submit cryptographically secure CSRF token in cookie + header.
 */

const crypto = require('node:crypto');

function csrfProtection(req, res, next) {
  // Ensure csrf token exists in cookie
  let csrfToken = req.cookies?.csrf_token;
  if (!csrfToken) {
    csrfToken = crypto.randomBytes(24).toString('hex');
    res.cookie('csrf_token', csrfToken, {
      httpOnly: false, // Must be readable by client JS to send in X-CSRF-Token header
      sameSite: 'Strict',
      secure: process.env.NODE_ENV === 'production',
      path: '/'
    });
  }

  // Safe HTTP methods do not require CSRF token
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) {
    return next();
  }

  // Skip CSRF for public AI voice query and signed webhooks (handles rewritten or routed paths)
  const path = req.path || '';
  const orig = req.originalUrl || '';
  if (
    path.startsWith('/api/webhooks/') ||
    path.includes('/api/ai-call/query') ||
    orig.includes('/api/ai-call/query') ||
    path.endsWith('/ai-call/query')
  ) {
    return next();
  }

  const clientToken = req.headers['x-csrf-token'] || req.body?._csrf;
  if (!clientToken || !csrfToken || clientToken !== csrfToken) {
    return res.status(403).json({
      success: false,
      error: 'CSRF_VALIDATION_FAILED: Invalid or missing CSRF token.',
      code: 'CSRF_ERROR'
    });
  }

  next();
}

module.exports = csrfProtection;
