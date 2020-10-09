const assert = require('assert');
const crypto = require('crypto');

// 7 - ASYMMETRIC ENCRYPTION - DECRYPTION

// ECC KEYS

async function ed25519_keys() {
  const type = 'ed25519';

  function getKeyPair(type) {
    return new Promise((resolve, reject) => {
      crypto.generateKeyPair(type, (err, publicKey, privateKey) => {
        err ? reject(err) : resolve({ publicKey, privateKey });
      });
    });
  }

  const { publicKey, privateKey } = await getKeyPair(type);

  return {
    publicKey: publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('hex'),
    privateKey: privateKey
      .export({
        type: 'pkcs8',
        format: 'der',
        cipher: 'aes-256-cbc',
        passphrase: 'top secret',
      })
      .toString('hex'),
  };
}

// ECDH KEY EXCHANGE
async function ecdh_brainpoolP256r1(
  alicePrivateKey = '12d323b77a03f9d57e6812de1fb0d508befd86eeee87fc44771dea3ab58dc0fa'
) {
  const curveName = 'brainpoolP256r1';

  const alice = crypto.createECDH(curveName);
  alice.setPrivateKey(alicePrivateKey, 'hex');

  alicePrivateKey = alice.getPrivateKey('hex');
  const aliceCompressedPublicKey = alice.getPublicKey('hex', 'compressed');
  const alicePublicKey = crypto.ECDH.convertKey(
    aliceCompressedPublicKey,
    curveName,
    'hex',
    'hex',
    'uncompressed'
  );
  console.log('aliceKeyPair : ', { alicePublicKey, alicePrivateKey });

  const bob = crypto.createECDH(curveName);
  bob.generateKeys();
  const bobPublicKey = bob.getPublicKey('hex');
  const bobPrivateKey = bob.getPrivateKey('hex');
  console.log('bobKeyPair : ', { bobPublicKey, bobPrivateKey });

  const aliceSecret = alice.computeSecret(bob.getPublicKey(), null, 'hex');
  const bobSecret = bob.computeSecret(alice.getPublicKey(), null, 'hex');

  assert.strictEqual(aliceSecret, bobSecret);

  return { aliceSecret, bobSecret };
}

// ECC ENCRYPTION / DECRYPTION

async function ecc_crypt_brainpoolP256r1(
  alicePrivateKey = '12d323b77a03f9d57e6812de1fb0d508befd86eeee87fc44771dea3ab58dc0fa'
) {
  const curveName = 'brainpoolP256r1';

  const alice = crypto.createECDH(curveName);
  alice.setPrivateKey(alicePrivateKey, 'hex');

  function calcEncryptionKeys(pubKey) {
    const ecdh = crypto.createECDH(curveName);
    ecdh.generateKeys();
    const cipherTextPubKey = ecdh.getPublicKey();
    // const cipherTextPrivKey = ecdh.getPrivateKey();
    const sharedECCKey = ecdh.computeSecret(pubKey, null, 'hex');
    return { sharedECCKey, cipherTextPubKey };
  }

  function calcDecryptionKey(privKey, cipherTextPubKey) {
    const ecdh = crypto.createECDH(curveName);
    ecdh.setPrivateKey(privKey);
    return ecdh.computeSecret(cipherTextPubKey, null, 'hex');
  }

  const { sharedECCKey: encryptKey, cipherTextPubKey } = calcEncryptionKeys(
    alice.getPublicKey()
  );

  const decryptKey = calcDecryptionKey(alice.getPrivateKey(), cipherTextPubKey);
  assert.strictEqual(encryptKey, decryptKey);

  return { encryptKey, decryptKey };
}

// ECC AES-GCM HYBRID ENCRYPTION / DECRYPTION
async function ecc_crypt_brainpoolP256r1_aes_gcm(
  plainText = `Text to be encrypted by ECC public key 
and decrypted by its corresponding ECC private key`,
  alicePrivateKey = '12d323b77a03f9d57e6812de1fb0d508befd86eeee87fc44771dea3ab58dc0fa',
  authTagLength = 16
) {
  const curveName = 'brainpoolP256r1';
  const cipherAlgorithm = 'aes-256-gcm';

  const alice = crypto.createECDH(curveName);
  alice.setPrivateKey(alicePrivateKey, 'hex');

  function encryptAES_GCM(msg, secretKey) {
    return new Promise((resolve, reject) => {
      let cipherText = '';
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(cipherAlgorithm, secretKey, iv, {
        authTagLength,
      });

      cipher.on('readable', () => {
        let chunk;
        while (null !== (chunk = cipher.read())) {
          cipherText += chunk.toString('hex');
        }
      });
      cipher.on('end', () => {
        const authTag = cipher.getAuthTag();
        resolve({ cipherText, iv, authTag });
      });
      cipher.on('error', (e) => {
        reject(e);
      });
      cipher.write(msg);
      cipher.end();
    });
  }

  function decryptAES_GCM(cipherText, iv, authTag, secretKey) {
    return new Promise((resolve, reject) => {
      let decipherText = '';
      const decipher = crypto.createDecipheriv(cipherAlgorithm, secretKey, iv, {
        authTagLength,
      });

      decipher.on('readable', () => {
        let chunk;
        while (null !== (chunk = decipher.read())) {
          decipherText += chunk.toString('utf8');
        }
      });

      decipher.on('end', () => {
        resolve(decipherText);
      });

      decipher.on('error', (e) => {
        reject(e);
      });

      decipher.setAuthTag(authTag);
      decipher.write(cipherText, 'hex');
      decipher.end();
    });
  }

  function eccPointTo256BitKey(sharedECCKey) {
    return crypto.createHash('sha256').update(sharedECCKey).digest();
  }

  async function encryptECC(msg, pubKey) {
    const ecdh = crypto.createECDH(curveName);
    ecdh.generateKeys();
    const cipherTextPubKey = ecdh.getPublicKey();
    // const cipherTextPrivKey = ecdh.getPrivateKey();
    const sharedECCKey = ecdh.computeSecret(pubKey);
    const secretKey = eccPointTo256BitKey(sharedECCKey);
    const { cipherText, iv, authTag } = await encryptAES_GCM(msg, secretKey);
    return { cipherText, iv, authTag, cipherTextPubKey };
  }

  async function decryptECC(encryptedMsg, privKey) {
    const { cipherText, iv, authTag, cipherTextPubKey } = encryptedMsg;
    const ecdh = crypto.createECDH(curveName);
    ecdh.setPrivateKey(privKey);
    const sharedECCKey = ecdh.computeSecret(cipherTextPubKey);
    const secretKey = eccPointTo256BitKey(sharedECCKey);
    return decryptAES_GCM(cipherText, iv, authTag, secretKey);
  }

  const { cipherText, iv, authTag, cipherTextPubKey } = await encryptECC(
    plainText,
    alice.getPublicKey()
  );

  const encryptedMsgObj = {
    cipherText,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    cipherTextPubKey: crypto.ECDH.convertKey(
      cipherTextPubKey,
      curveName,
      null,
      'hex',
      'compressed'
    ).slice(2),
  };
  console.log(encryptedMsgObj);

  const decryptedText = await decryptECC(
    { cipherText, iv, authTag, cipherTextPubKey },
    alice.getPrivateKey()
  );

  assert.strictEqual(plainText, decryptedText);

  return { encryptedText: cipherText, decryptedText };
}

module.exports = {
  ed25519_keys,
  ecdh_brainpoolP256r1,
  ecc_crypt_brainpoolP256r1,
  ecc_crypt_brainpoolP256r1_aes_gcm,
};
