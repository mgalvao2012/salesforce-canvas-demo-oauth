var crypto = require('crypto');

/**
 * Verifies the Canvas signed_request HMAC and decodes the envelope.
 * Returns the decoded envelope object, or null if verification fails.
 */
function decodeSignedRequest(signedRequest, secret) {
  const parts = signedRequest.split('.');
  if (parts.length !== 2) return null;
  const [consumerSecret, encodedEnvelope] = parts;
  const check = crypto
    .createHmac('sha256', secret)
    .update(encodedEnvelope)
    .digest('base64');
  if (check !== consumerSecret) return null;
  return JSON.parse(Buffer.from(encodedEnvelope, 'base64').toString('ascii'));
}

module.exports = { decodeSignedRequest };
