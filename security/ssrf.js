/**
 * THE OPTICAL HUB — SSRF Protection Module
 * Checklist #5: SSRF Protection
 * 
 * Validates outgoing URLs (e.g. for Webhook notifications, external SMS/WhatsApp gateways)
 * Blocks private IP ranges, loopback, link-local, and AWS/Cloud metadata endpoints.
 */

const { URL } = require('node:url');

const BLOCKED_IP_PATTERNS = [
  /^127\./,                         // Loopback (127.0.0.0/8)
  /^10\./,                          // Private class A (10.0.0.0/8)
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private class B (172.16.0.0/12)
  /^192\.168\./,                    // Private class C (192.168.0.0/16)
  /^169\.254\./,                    // Link-local / Cloud Metadata (169.254.169.254)
  /^0\.0\.0\.0/,                    // Any local address
  /^localhost$/i,                   // Localhost
  /^::1$/,                          // IPv6 loopback
  /^fc00:/i,                        // IPv6 unique local
  /^fe80:/i                         // IPv6 link-local
];

function validateSafeUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);

    // Only allow http or https protocols
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { safe: false, reason: 'Disallowed protocol: Only HTTP/HTTPS allowed.' };
    }

    const hostname = parsed.hostname.toLowerCase();

    // Check against blocked patterns
    for (const pattern of BLOCKED_IP_PATTERNS) {
      if (pattern.test(hostname)) {
        return {
          safe: false,
          reason: `SSRF_BLOCKED: Outbound request to private/internal network destination (${hostname}) is strictly prohibited.`
        };
      }
    }

    return { safe: true, url: parsed.toString() };
  } catch (err) {
    return { safe: false, reason: 'Invalid URL format.' };
  }
}

module.exports = { validateSafeUrl };
