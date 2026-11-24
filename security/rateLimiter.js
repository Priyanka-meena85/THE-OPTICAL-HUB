/**
 * THE OPTICAL HUB — Rate Limiting Suite
 * Checklist #7: Rate Limiting lagao (koi baar-baar password try na kare)
 */

const rateLimit = require('express-rate-limit');

// Strict rate limiter for Authentication endpoints (Login, Register, MFA)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'TOO_MANY_REQUESTS: Too many authentication attempts. Please wait 15 minutes before trying again.',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

// Rate limiter for 24/7 AI Night Calling Voice Agent
const aiCallingLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // 20 voice queries per 5 min
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'AI_CALL_RATE_LIMIT: Voice assistant busy. Please wait a few moments.',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

// General API Rate Limiter
const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 120, // 120 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'RATE_LIMIT_EXCEEDED: General request limit exceeded.',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

module.exports = {
  authLimiter,
  aiCallingLimiter,
  generalLimiter
};
