const assert = require('assert');
const crypto = require('crypto');
const forge = require('node-forge');

// 7 - ASYMMETRIC ENCRYPTION - DECRYPTION

// RSA-OAEP
async function rsa_oaep(
  plainText = 'Message to encrypt',
  modulusLength = 3072,
  padding = crypto.constants.RSA_PKCS1_OAEP_PADDING
) {
  const type = 'rsa';

  function getKeyPair() {
    return new Promise((resolve, reject) => {
      crypto.generateKeyPair(
        type,
        { modulusLength },
        (err, publicKey, privateKey) => {
          err ? reject(err) : resolve({ publicKey, privateKey });
        }
      );
    });
  }

  function encrypt(publicKey, padding, buffer) {
    return crypto.publicEncrypt({ key: publicKey, padding }, buffer);
  }

  function decrypt(privateKey, padding, buffer) {
    return crypto.privateDecrypt({ key: privateKey, padding }, buffer);
  }

  const { publicKey, privateKey } = await getKeyPair();
  // console.log({
  //   publicKey: publicKey.export({type: 'pkcs1', format: 'pem'}),
  //   privateKey: privateKey.export({type: 'pkcs1', format: 'pem'})
  // })
  const encryptedMessage = encrypt(publicKey, padding, Buffer.from(plainText));
  const decryptedMessage = decrypt(privateKey, padding, encryptedMessage);
  assert.strictEqual(plainText, decryptedMessage.toString('utf-8'));

  return {
    encryptedText: encryptedMessage.toString('hex'),
    decryptedText: decryptedMessage.toString('utf-8'),
  };
}

// RSA+KEM

// WITH NATIVE NODE
async function rsa_kem_native(
  plainText = 'hello world!',
  modulusLength = 3072
) {
  const type = 'rsa';
  const cipherAlgorithm = 'aes-128-gcm';
  const pki = forge.pki;

  function getKeyPair() {
    return new Promise((resolve, reject) => {
      crypto.generateKeyPair(
        type,
        { modulusLength },
        (err, publicKey, privateKey) => {
          err ? reject(err) : resolve({ publicKey, privateKey });
        }
      );
    });
  }

  function getKem() {
    // TODO: replace by node API
    // see https://github.com/digitalbazaar/forge/blob/588c41062d9a13f8dc91be3723b159c6cc434b15/lib/kem.js#L111
    const kdf1 = new forge.kem.kdf1(forge.md.sha1.create());
    return forge.kem.rsa.create(kdf1);
  }

  function encrypt({ publicKey, plainText }) {
    const publicKeyPem = publicKey.export({ type: 'pkcs1', format: 'pem' });
    publicKey = pki.publicKeyFromPem(publicKeyPem);

    // generate and encapsulate a 16-byte secret key
    const kem = getKem();
    const { key: encryptionKey, encapsulation } = kem.encrypt(publicKey, 16);

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(
      cipherAlgorithm,
      Buffer.from(encryptionKey, 'ascii'),
      iv,
      {
        authTagLength: 16,
      }
    );

    const encrypted = cipher.update(plainText, 'utf8');
    cipher.final();
    const tag = cipher.getAuthTag();
    return { encrypted, encapsulation, iv, tag };
  }

  function decrypt({ privateKey, encapsulation, encrypted, iv }) {
    const privateKeyPem = privateKey.export({ type: 'pkcs1', format: 'pem' });
    privateKey = pki.privateKeyFromPem(privateKeyPem);

    // decrypt encapsulated 16-byte secret key
    // TODO: replace by node API
    const kem = getKem();
    const key = kem.decrypt(privateKey, encapsulation, 16);

    const decipher = crypto.createDecipheriv(
      cipherAlgorithm,
      Buffer.from(key, 'ascii'),
      iv,
      {
        authTagLength: 16,
      }
    );

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    try {
      decipher.setAuthTag(tag);
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (e) {
      return null;
    }
  }

  const { publicKey, privateKey } = await getKeyPair(type, modulusLength);
  const { encrypted, encapsulation, iv, tag } = encrypt({
    publicKey,
    plainText,
  });
  const decrypted = decrypt({ privateKey, encapsulation, encrypted, iv });
  assert.strictEqual(plainText, decrypted.toString('utf-8'));

  return {
    encryptedText: encrypted.toString('utf-8'),
    decryptedText: decrypted.toString('utf-8'),
  };
}

// WITH FORGE LIB
async function rsa_kem_forge(plainText = 'hello world!', modulusLength = 3072) {
  const type = 'rsa';
  const cipherAlgorithm = 'AES-GCM';

  function getKeyPair(type, modulusLength) {
    return new Promise((resolve, reject) => {
      forge.rsa.generateKeyPair(
        { bits: modulusLength, workers: -1 },
        (err, keypair) => {
          err ? reject(err) : resolve(keypair);
        }
      );
    });
  }

  function encrypt({ publicKey, plainText }) {
    // generate and encapsulate a 16-byte secret key
    const kdf1 = new forge.kem.kdf1(forge.md.sha1.create());
    const kem = forge.kem.rsa.create(kdf1);
    const { key: encryptionKey, encapsulation } = kem.encrypt(publicKey, 16);

    const iv = crypto.randomBytes(12);
    const cipher = forge.cipher.createCipher(cipherAlgorithm, encryptionKey);
    cipher.start({ iv });
    cipher.update(forge.util.createBuffer(plainText));
    cipher.finish();
    const encrypted = cipher.output.getBytes();
    const tag = cipher.mode.tag.getBytes();
    return { encrypted, encapsulation, iv, tag };
  }

  function decrypt({ privateKey, encapsulation, encrypted, iv }) {
    // decrypt encapsulated 16-byte secret key
    const kdf1 = new forge.kem.kdf1(forge.md.sha1.create());
    const kem = forge.kem.rsa.create(kdf1);
    const key = kem.decrypt(privateKey, encapsulation, 16);

    const decipher = forge.cipher.createDecipher(cipherAlgorithm, key);
    decipher.start({ iv, tag });
    decipher.update(forge.util.createBuffer(encrypted));
    const pass = decipher.finish();
    const decrypted = decipher.output.getBytes();
    return pass ? decrypted : null;
  }

  const { publicKey, privateKey } = await getKeyPair(type, modulusLength);
  const { encrypted, encapsulation, iv, tag } = encrypt({
    publicKey,
    plainText,
  });
  const decrypted = decrypt({ privateKey, encapsulation, encrypted, iv });
  assert.strictEqual(plainText, decrypted.toString('utf-8'));

  return {
    encryptedText: encrypted.toString('utf-8'),
    decryptedText: decrypted.toString('utf-8'),
  };
}

module.exports = {
  rsa_oaep,
  rsa_kem_native,
  rsa_kem_forge,
};
