const crypto = require('crypto');

// 1 - HASH
function simpleHash(alg = 'sha256', msg = 'hello') {
  return crypto.createHash(alg).update(msg).digest();
}

module.exports = {
  simpleHash,
};
