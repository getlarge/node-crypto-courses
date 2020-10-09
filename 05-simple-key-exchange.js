const assert = require('assert');
const crypto = require('crypto');

// 5 - KEY EXCHANGE

// DIFFIE HELLMAN
function diffieHellman(primeLength = 1024) {
  const alice = crypto.createDiffieHellman(primeLength);
  const aliceKey = alice.generateKeys();
  console.log('Alice key', aliceKey.toString('hex'));

  const bob = crypto.createDiffieHellman(
    alice.getPrime(),
    alice.getGenerator()
  );
  const bobKey = bob.generateKeys();
  console.log('Bob key', bobKey.toString('hex'));

  const aliceSecret = alice.computeSecret(bobKey);
  const bobSecret = bob.computeSecret(aliceKey);

  assert.strictEqual(aliceSecret.toString('hex'), bobSecret.toString('hex'));

  return { aliceSecret, bobSecret };
}

module.exports = {
  diffieHellman,
};
