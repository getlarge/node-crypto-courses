const assert = require('assert');
const crypto = require('crypto');
const ecies = require('standard-ecies');

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
  privateKey = '12d323b77a03f9d57e6812de1fb0d508befd86eeee87fc44771dea3ab58dc0fa',
  authTagLength = 16
) {
  const curveName = 'brainpoolP256r1';
  const cipherAlgorithm = 'aes-256-gcm';

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

  const ecdh = crypto.createECDH(curveName);
  ecdh.setPrivateKey(privateKey, 'hex');

  const { cipherText, iv, authTag, cipherTextPubKey } = await encryptECC(
    plainText,
    ecdh.getPublicKey()
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
    ecdh.getPrivateKey()
  );

  assert.strictEqual(plainText, decryptedText);

  return { encryptedText: cipherText, decryptedText };
}

// ECIES Encryption
async function native_ecies_crypto(
  plainText = 'secret message',
  privateKey = null,
  options = {
    hashName: 'sha256',
    hashLength: 32,
    macName: 'sha256',
    macLength: 32,
    authTagLength: 16,
    // curveName: 'brainpoolP256r1',
    // cipherAlgorithm: 'aes-256-gcm',
    curveName: 'secp256k1',
    // cipherAlgorithm: 'aes-128-cbc',
    cipherAlgorithm: 'chacha20-poly1305',
    iv: null,
    keyFormat: 'uncompressed',
    encoding: {
      inputKey: 'hex',
      input: 'utf8',
      output: 'utf8',
    },
    s1: Buffer.allocUnsafe(0),
    s2: Buffer.allocUnsafe(0),
  }
) {
  function getDerivedKeys(sharedSecret, { hashName, s1 }) {
    const hash = crypto
      .createHash(hashName)
      .update(
        Buffer.concat([sharedSecret, s1], sharedSecret.length + s1.length)
      )
      .digest();

    const encryptionKey = hash.slice(0, hash.length / 2);
    const macKey = hash.slice(hash.length / 2);
    return { encryptionKey, macKey };
  }

  function getAuthTag(cipherText, macKey, { macName, s2 }) {
    return crypto
      .createHmac(macName, macKey)
      .update(Buffer.concat([cipherText, s2], cipherText.length + s2.length))
      .digest();
  }

  function symmetricEncrypt(
    input,
    key,
    { cipherAlgorithm, iv, authTagLength }
  ) {
    return new Promise((resolve) => {
      const cipher = crypto.createCipheriv(cipherAlgorithm, key, iv, {
        authTagLength,
      });

      const cipherText = cipher.update(input);
      cipher.final();
      const authTag = cipher.getAuthTag();
      resolve({ cipherText, iv, authTag });
    });
  }

  async function encrypt(publicKey, message, options) {
    const ecdh = crypto.createECDH(options.curveName);
    const R = ecdh.generateKeys(null, options.keyFormat);
    const sharedSecret = ecdh.computeSecret(publicKey);

    const { encryptionKey, macKey } = getDerivedKeys(sharedSecret, options);
    const { cipherText, iv, authTag } = await symmetricEncrypt(
      message,
      encryptionKey,
      options
    );
    console.log({ authTag });
    const tag = getAuthTag(cipherText, macKey, options);
    return Buffer.concat([R, cipherText, tag]);
  }

  function symmetricDecrypt(
    cipherBuffer,
    key,
    { cipherAlgorithm, iv, authTagLength, encoding },
    authTag
  ) {
    return new Promise((resolve, reject) => {
      let decipherData =
        typeof encoding.output === 'string' ? '' : Buffer.allocUnsafe(0);
      iv = iv || Buffer.allocUnsafe(0);

      const decipher = crypto.createDecipheriv(cipherAlgorithm, key, iv, {
        authTagLength,
      });
      // .setAAD(s1);

      if (authTag) {
        decipher.setAuthTag(authTag);
      }

      decipherData =
        typeof encoding.output === 'string'
          ? decipher.update(cipherBuffer, null, encoding.output)
          : decipher.update(cipherBuffer);

      try {
        decipher.setAuthTag(authTag);
        if (typeof encoding.output === 'string') {
          decipherData += decipher.final(null, encoding.output);
        } else {
          const lastChunk = decipher.final();
          decipherData = Buffer.concat(
            [decipherData, lastChunk],
            decipherData.length + lastChunk.length
          );
        }
        resolve(decipherData);
      } catch (e) {
        reject(e);
      }
    });
  }

  async function decrypt(ecdh, message, options) {
    const publicKeyLength = ecdh.getPublicKey(null, options.keyFormat).length;
    const R = message.slice(0, publicKeyLength);
    const cipherText = message.slice(
      publicKeyLength,
      message.length - options.macLength
    );

    const messageTag = message.slice(message.length - options.macLength);
    const sharedSecret = ecdh.computeSecret(R);
    const { encryptionKey, macKey } = getDerivedKeys(sharedSecret, options);
    const tag = getAuthTag(cipherText, macKey, options);

    if (!crypto.timingSafeEqual(messageTag, tag)) {
      throw new Error('Bad MAC');
    }

    return symmetricDecrypt(cipherText, encryptionKey, options);
  }

  function getIV(cipherAlgorithm, iv) {
    // TODO check cipherAlgorithm to set the right size
    if (iv !== null && iv !== undefined) {
      return iv;
    }
    if (cipherAlgorithm.includes('ecb')) {
      return crypto.randomBytes(0);
    }
    if (cipherAlgorithm.includes('chacha20')) {
      return crypto.randomBytes(12);
    }
    return crypto.randomBytes(16);
  }

  function generateKeys(privateKey, { curveName, encoding }) {
    const ecdh = crypto.createECDH(curveName);
    if (privateKey && privateKey instanceof Buffer) {
      ecdh.setPrivateKey(options.privateKey);
    } else if (
      privateKey &&
      typeof privateKey === 'string' &&
      typeof encoding.inputKey === 'string'
    ) {
      ecdh.setPrivateKey(options.privateKey, encoding.inputKey);
    } else {
      ecdh.generateKeys();
    }
    return ecdh;
  }

  function getPlainTextBuffer(text, encoding) {
    if (typeof text === 'string' && typeof encoding.input === 'string') {
      return Buffer.from(text, encoding.input);
    }
    return text;
  }

  const ecdh = generateKeys(privateKey, options);
  plainText = getPlainTextBuffer(plainText, options.encoding);
  options.iv = getIV(options.cipherAlgorithm, options.iv);

  const encryptedText = await encrypt(ecdh.getPublicKey(), plainText, options);
  const decryptedText = await decrypt(ecdh, encryptedText, options);

  assert(plainText.toString('hex') === decryptedText.toString('hex'));

  return {
    encryptedText: encryptedText.toString('hex'),
    decryptedText: decryptedText.toString('utf8'),
  };
}

// USING standard-ecies lib
function ecies_crypto(
  plainText = 'hello world',
  privateKey = null,
  options = {
    hashName: 'sha256',
    hashLength: 32,
    macName: 'sha256',
    macLength: 32,
    // curveName: 'secp256k1',
    symmetricCypherName: 'aes-128-ecb',
    curveName: 'brainpoolP256r1',
    // symmetricCypherName: 'chacha20-poly1305',
    iv: null,
    keyFormat: 'uncompressed',
    encoding: {
      inputKey: 'hex',
      input: 'utf8',
      output: 'utf8',
    },
    s1: null, // optional shared information1
    s2: null, // optional shared information2
  }
) {
  ecies.getIV = (cipherAlgorithm, iv) => {
    // TODO check cipherAlgorithm to set the right size
    if (iv !== null && iv !== undefined) {
      return iv;
    }
    if (cipherAlgorithm.includes('ecb')) {
      return crypto.randomBytes(0);
    }
    if (cipherAlgorithm.includes('chacha20')) {
      return crypto.randomBytes(12);
    }
    return crypto.randomBytes(16);
  };

  ecies.generateKeys = (privateKey, { curveName, encoding }) => {
    const ecdh = crypto.createECDH(curveName);
    if (privateKey && privateKey instanceof Buffer) {
      ecdh.setPrivateKey(options.privateKey);
    } else if (
      privateKey &&
      typeof privateKey === 'string' &&
      typeof encoding.inputKey === 'string'
    ) {
      ecdh.setPrivateKey(options.privateKey, encoding.inputKey);
    } else {
      ecdh.generateKeys();
    }
    return ecdh;
  };

  ecies.getPlainTextBuffer = (text, encoding) => {
    if (typeof text === 'string' && typeof encoding.input === 'string') {
      return Buffer.from(text, encoding.input);
    }
    return text;
  };

  const ecdh = ecies.generateKeys(privateKey, options);
  plainText = ecies.getPlainTextBuffer(plainText, options.encoding);
  options.iv = ecies.getIV(options.symmetricCypherName, options.iv);

  const encryptedText = ecies.encrypt(ecdh.getPublicKey(), plainText, options);
  const decryptedText = ecies.decrypt(ecdh, encryptedText, options);

  assert(plainText.toString('hex') === decryptedText.toString('hex'));

  return {
    encryptedText: encryptedText.toString('hex'),
    decryptedText: options.encoding.output
      ? decryptedText.toString(options.encoding.output)
      : decryptedText,
  };
}

module.exports = {
  ed25519_keys,
  ecdh_brainpoolP256r1,
  ecc_crypt_brainpoolP256r1,
  ecc_crypt_brainpoolP256r1_aes_gcm,
  native_ecies_crypto,
  ecies_crypto,
};
