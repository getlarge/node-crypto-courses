const crypto = require('crypto');

// 2 - HMAC
function simpleHmac(alg = 'sha256', key = 'cryptography', msg = 'hello') {
  return crypto.createHmac(alg, key).update(msg).digest();
}

module.exports = {
  simpleHmac,
};
