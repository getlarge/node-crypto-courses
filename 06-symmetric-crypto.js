const assert = require('assert');
const crypto = require('crypto');

// 6 - SYMMETRIC ENCRYPTION - DECRYPTION

// AES-256-CTR
async function aes_256_ctr(plainText = 'secretMsg', password = 'p@sSw0rd~123') {
  const algorithm = 'aes-256-ctr';
  const passwordSalt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, passwordSalt, 32);

  function encrypt(textToEncrypt) {
    return new Promise((resolve) => {
      let cipherText = '';
      const iv = crypto.randomBytes(16);
      const aes = crypto.createCipheriv(algorithm, key, iv);

      aes.on('readable', () => {
        let chunk;
        while (null !== (chunk = aes.read())) {
          cipherText += chunk.toString('hex');
        }
      });
      aes.on('end', () => {
        resolve({ cipherText, iv });
      });

      aes.write(textToEncrypt);
      aes.end();
    });
  }

  function decrypt(encryptedText, iv) {
    return new Promise((resolve) => {
      let decipherText = '';
      const aes = crypto.createDecipheriv(algorithm, key, iv);

      aes.on('readable', () => {
        let chunk;
        while (null !== (chunk = aes.read())) {
          decipherText += chunk.toString('utf8');
        }
      });
      aes.on('end', () => {
        resolve(decipherText);
      });

      aes.write(encryptedText, 'hex');
      aes.end();
    });
  }

  const { cipherText: encryptedText, iv } = await encrypt(plainText);
  const decryptedText = await decrypt(encryptedText, iv);

  assert.strictEqual(plainText, decryptedText);

  return { encryptedText, decryptedText };
}

// KDF + CHACHA20-POLY1305
async function chacha20_poly1305(
  plainText = 'secretMsg',
  password = 'p@sSw0rd~123'
) {
  const algorithm = 'chacha20-poly1305';
  let assocData = Buffer.alloc(16, 0xaa);

  function encrypt({ password, plainText }) {
    const iv = crypto.randomBytes(12);
    const passwordSalt = crypto.randomBytes(16);
    const key = crypto.scryptSync(password, passwordSalt, 32);
    let encryptedText = '';

    return new Promise((resolve) => {
      const cipher = crypto
        .createCipheriv(algorithm, key, iv, {
          authTagLength: 16,
        })
        .setAAD(assocData);

      cipher.on('readable', () => {
        let chunk;
        while (null !== (chunk = cipher.read())) {
          encryptedText += chunk.toString('hex');
        }
      });

      cipher.on('end', () => {
        const authTag = cipher.getAuthTag();
        resolve({ encryptedText, iv, authTag, salt: passwordSalt });
      });

      cipher.write(plainText);
      cipher.end();
    });
  }

  function decrypt({ password, salt, encryptedText, iv, authTag }) {
    const key = crypto.scryptSync(password, salt, 32);
    let decryptedText = '';

    return new Promise((resolve, reject) => {
      const decipher = crypto
        .createDecipheriv(algorithm, key, iv, {
          authTagLength: 16,
        })
        .setAAD(assocData);

      decryptedText = decipher.update(encryptedText, 'hex', 'utf8');
      try {
        decipher.setAuthTag(authTag);
        decryptedText += decipher.final('utf8');
        resolve(decryptedText);
      } catch (e) {
        reject(e);
      }
    });
  }

  const { encryptedText, iv, authTag, salt } = await encrypt({
    password,
    plainText,
  });
  const decryptedText = await decrypt({
    password,
    salt,
    encryptedText,
    iv,
    authTag,
  });

  assert.strictEqual(plainText, decryptedText);

  return { encryptedText, decryptedText };
}

// KDF + AES-256-CBC + HMAC
async function aes_256_cbc_hmac(
  plainText = 'secretMsg',
  password = 'p@sSw0rd~123'
) {
  const cipherAlgorithm = 'aes-256-cbc';
  const hmacAlgorithm = 'sha256';

  function getDerivedKeys({ password, salt }) {
    return new Promise((resolve, reject) => {
      crypto.scrypt(
        password,
        salt,
        64,
        { n: 16384, r: 8, p: 1 },
        (err, derivedKey) => {
          if (err) {
            return reject(err);
          }
          const encryptionKey = derivedKey.slice(0, 32);
          const hmacKey = derivedKey.slice(32);
          resolve({ encryptionKey, hmacKey });
        }
      );
    });
  }

  async function encrypt({ password, plainText }) {
    const salt = crypto.randomBytes(16);
    const { encryptionKey, hmacKey } = await getDerivedKeys({ password, salt });
    const iv = crypto.randomBytes(16);

    return new Promise((resolve, reject) => {
      let encryptedText = '';
      const cipher = crypto
        .createCipheriv(cipherAlgorithm, encryptionKey, iv)
        .setAutoPadding(true);

      cipher.on('readable', () => {
        let chunk;
        while (null !== (chunk = cipher.read())) {
          encryptedText += chunk.toString('hex');
        }
      });

      cipher.on('end', () => {
        const mac = crypto
          .createHmac(hmacAlgorithm, hmacKey)
          .update(encryptedText)
          .digest('hex');
        const result = {
          iv: iv.toString('hex'),
          salt: salt.toString('hex'),
          mac,
          encryptedText,
        };
        resolve(result);
      });

      cipher.on('error', (e) => {
        reject(e);
      });

      cipher.write(plainText);
      cipher.end();
    });
  }

  async function decrypt({ password, encryptResult }) {
    const { iv, salt, mac, encryptedText } = encryptResult;
    const { encryptionKey, hmacKey } = await getDerivedKeys({
      password,
      salt: Buffer.from(salt, 'hex'),
    });

    const comparedMac = crypto
      .createHmac(hmacAlgorithm, hmacKey)
      .update(encryptedText)
      .digest('hex');

    if (mac !== comparedMac) {
      throw new Error('Invalid MAC');
    }

    return new Promise((resolve) => {
      let decryptedText = '';
      const decipher = crypto
        .createDecipheriv(
          cipherAlgorithm,
          encryptionKey,
          Buffer.from(iv, 'hex')
        )
        .setAutoPadding(true);

      decipher.on('readable', () => {
        let chunk;
        while (null !== (chunk = decipher.read())) {
          decryptedText += chunk.toString('utf8');
        }
      });

      decipher.on('end', () => {
        resolve(decryptedText);
      });

      decipher.on('error', (err) => {
        reject(err);
      });

      decipher.write(encryptedText, 'hex');
      decipher.end();
    });
  }

  const encryptResult = await encrypt({ password, plainText });
  const decryptedText = await decrypt({ encryptResult, password });

  assert.strictEqual(plainText, decryptedText);

  return { encryptedText: encryptResult.encryptedText, decryptedText };
}

module.exports = {
  aes_256_ctr,
  chacha20_poly1305,
  aes_256_cbc_hmac,
};
