/**
 * THE OPTICAL HUB — Webhook Signature Verifier
 * Checklist #18: Webhook Signatures verify karo
 * 
 * Verifies incoming HMAC-SHA256 signatures for Clinic WhatsApp Webhooks
 * and Online Payment (Razorpay/UPI) Webhooks.
 */

const crypto = require('node:crypto');

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'OpticalHub_Jaipur_WebhookSecret_2026_@_SecureSignature';

function verifyWebhookSignature(payloadBuffer, signatureHeader) {
  if (!signatureHeader || !payloadBuffer) return false;

  const expectedSignature = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(payloadBuffer)
    .digest('hex');

  // Strip sha256= prefix if sent by provider (like GitHub/Meta)
  const cleanSignature = signatureHeader.replace(/^sha256=/i, '');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(cleanSignature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  } catch (err) {
    return false;
  }
}

function webhookSignatureMiddleware(req, res, next) {
  const signature = req.headers['x-hub-signature-256'] || req.headers['x-webhook-signature'];
  if (!signature) {
    return res.status(401).json({
      success: false,
      error: 'WEBHOOK_SIGNATURE_MISSING: Incoming webhook lacks HMAC-SHA256 signature.',
      code: 'UNAUTHORIZED_WEBHOOK'
    });
  }

  // Uses rawBody saved during express json parsing
  const isVerified = verifyWebhookSignature(req.rawBody || JSON.stringify(req.body), signature);
  if (!isVerified) {
    return res.status(403).json({
      success: false,
      error: 'WEBHOOK_SIGNATURE_INVALID: Tampered or unauthorized webhook payload.',
      code: 'FORBIDDEN_WEBHOOK'
    });
  }

  next();
}

module.exports = {
  verifyWebhookSignature,
  webhookSignatureMiddleware,
  WEBHOOK_SECRET
};
