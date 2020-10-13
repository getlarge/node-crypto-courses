const crypto = require('crypto');
const { getInputBuffer } = require('./utils');

// 9 - DIGITAL SIGNATURES
function rsa_signature(
  msg = 'hello',
  options = { modulusLength: 3072, alg: 'sha3-512' }
) {
  const type = 'rsa';
  const { modulusLength } = options;

  const { privateKey, publicKey } = crypto.generateKeyPairSync(type, {
    modulusLength,
  });

  function signing(msg, privateKey, { alg }) {
    const sign = crypto.createSign(alg);
    sign.update(msg);
    sign.end();
    return sign.sign(privateKey);
  }

  function verifying(msg, publicKey, signature, { alg }) {
    const verify = crypto.createVerify(alg);
    verify.update(msg);
    verify.end();
    return verify.verify(publicKey, signature);
  }

  const signature = signing(msg, privateKey, options);
  const signatureIsValid = verifying(msg, publicKey, signature, options);
  return { signature, signatureIsValid };
}

function ec_signature(
  msg = 'hello',
  options = { namedCurve: 'secp256k1', alg: 'sha256' }
) {
  const type = 'ec';
  const { namedCurve } = options;

  const { privateKey, publicKey } = crypto.generateKeyPairSync(type, {
    namedCurve,
  });

  function signing(msg, privateKey, { alg }) {
    const sign = crypto.createSign(alg);
    sign.write(msg);
    sign.end();
    return sign.sign(privateKey);
  }

  function verifying(msg, publicKey, signature, { alg }) {
    const verify = crypto.createVerify(alg);
    verify.write(msg);
    verify.end();
    return verify.verify(publicKey, signature);
  }

  const signature = signing(msg, privateKey, options);
  const signatureIsValid = verifying(msg, publicKey, signature, options);
  return { signature, signatureIsValid };
}

function ed25519_signature(msg = 'hello') {
  const type = 'ed25519';

  const { privateKey, publicKey } = crypto.generateKeyPairSync(type);

  function signing(msg, privateKey) {
    return crypto.sign(null, msg, privateKey);
  }

  function verifying(msg, publicKey, signature) {
    return crypto.verify(null, msg, publicKey, signature);
  }

  msg = getInputBuffer(msg);
  const signature = signing(msg, privateKey);
  const signatureIsValid = verifying(msg, publicKey, signature);
  return { signature, signatureIsValid };
}

function ed448_signature(msg = 'hello') {
  const type = 'ed448';

  const { privateKey, publicKey } = crypto.generateKeyPairSync(type);

  function signing(msg, privateKey) {
    return crypto.sign(null, msg, privateKey);
  }

  function verifying(msg, publicKey, signature) {
    return crypto.verify(null, msg, publicKey, signature);
  }

  msg = getInputBuffer(msg);
  const signature = signing(msg, privateKey);
  const signatureIsValid = verifying(msg, publicKey, signature);
  return { signature, signatureIsValid };
}

module.exports = {
  rsa_signature,
  ec_signature,
  ed25519_signature,
  ed448_signature,
};
