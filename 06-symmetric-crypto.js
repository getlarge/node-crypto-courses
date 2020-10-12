const assert = require('assert');
const crypto = require('crypto');
const combine = require('multipipe');
const {
  measureExecutionTime,
  getInputBuffer,
  getReadableStream,
  appendToStream,
  removeFromStream,
} = require('./utils');

// 6 - SYMMETRIC ENCRYPTION - DECRYPTION
function getScryptKey({ password, salt, keyLength }) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keyLength, (err, key) => {
      err ? reject(err) : resolve(key);
    });
  });
}

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

function aes_256_ctr_stream(
  input = 'secretMsg',
  password = 'p@sSw0rd~123',
  options = {
    encoding: {
      input: 'utf8',
    },
  }
) {
  const algorithm = 'aes-256-ctr';
  const passwordSalt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, passwordSalt, 32);
  const iv = crypto.randomBytes(16);

  input = getReadableStream(input);

  return combine(
    input
      .pipe(crypto.createCipheriv(algorithm, key, iv))
      .pipe(crypto.createDecipheriv(algorithm, key, iv))
  );
}

// KDF + CHACHA20-POLY1305
async function chacha20_poly1305(
  input = 'secretMsg',
  password = 'p@sSw0rd~123',
  options = {
    algorithm: 'chacha20-poly1305',
    encoding: {
      input: 'utf8',
    },
    ivLength: 12,
    authTagLength: 16,
    keyLength: 32,
    saltLength: 16,
    assocData: Buffer.alloc(16, 0xaa),
  }
) {
  async function getEncryptionParam(
    password,
    { assocData, ivLength, saltLength, keyLength }
  ) {
    const iv = crypto.randomBytes(ivLength);
    const salt = crypto.randomBytes(saltLength);
    const key = await getScryptKey({ password, salt, keyLength });
    return { key, iv, salt, assocData };
  }

  function encrypt(
    input,
    { key, salt, iv },
    { algorithm, assocData, encoding, authTagLength }
  ) {
    return new Promise((resolve) => {
      const cipher = crypto
        .createCipheriv(algorithm, key, iv, {
          authTagLength,
        })
        .setAAD(assocData);

      let encryptedBuffer = cipher.update(input);
      cipher.final();
      const authTag = cipher.getAuthTag();
      encryptedBuffer = Buffer.concat(
        [iv, salt, authTag, encryptedBuffer],
        iv.length + salt.length + authTag.length + encryptedBuffer.length
      );
      resolve(encryptedBuffer);
    });
  }

  async function getDecryptionParam(
    input,
    password,
    { assocData, ivLength, saltLength, keyLength, authTagLength }
  ) {
    const iv = input.slice(0, ivLength);
    const salt = input.slice(ivLength, ivLength + saltLength);
    const authTag = input.slice(
      ivLength + saltLength,
      ivLength + saltLength + authTagLength
    );
    const key = await getScryptKey({ password, salt, keyLength });
    return { key, iv, salt, assocData, authTag };
  }

  function decrypt(
    input,
    { key, iv, authTag },
    { algorithm, assocData, authTagLength, ivLength, saltLength }
  ) {
    let decryptedData = '';
    const cipherBuffer = input.slice(ivLength + saltLength + authTagLength);

    return new Promise((resolve, reject) => {
      const decipher = crypto
        .createDecipheriv(algorithm, key, iv, {
          authTagLength,
        })
        .setAAD(assocData);

      decryptedData = decipher.update(cipherBuffer);
      try {
        decipher.setAuthTag(authTag);
        const lastChunk = decipher.final();
        decryptedData = Buffer.concat(
          [decryptedData, lastChunk],
          decryptedData.length + lastChunk.length
        );
        resolve(decryptedData);
      } catch (e) {
        reject(e);
      }
    });
  }

  const hrstart = process.hrtime();
  input = getInputBuffer(input, options.encoding);

  const encryptionParam = await getEncryptionParam(password, options);
  measureExecutionTime(hrstart, 'getEncryptionParam');
  const encryptedData = await encrypt(input, encryptionParam, options);
  measureExecutionTime(hrstart, 'read encryptData');

  const decryptionParam = await getDecryptionParam(
    encryptedData,
    password,
    options
  );
  measureExecutionTime(hrstart, 'getDecryptionParam');
  const decryptedData = await decrypt(encryptedData, decryptionParam, options);
  measureExecutionTime(hrstart, 'read decryptData');

  assert.strictEqual(input.toString('utf8'), decryptedData.toString('utf8'));

  return {
    encryptedText: encryptedData.toString('hex'),
    decryptedText: decryptedData.toString('utf8'),
  };
}

async function chacha20_poly1305_stream(
  input = 'secretMsg',
  password = 'p@sSw0rd~123',
  options = {
    algorithm: 'chacha20-poly1305',
    encoding: {
      input: 'utf8',
    },
    ivLength: 12,
    authTagLength: 16,
    keyLength: 32,
    saltLength: 16,
    assocData: Buffer.alloc(16, 0xaa),
  }
) {
  async function getEncryptionParam(
    password,
    { assocData, ivLength, saltLength, keyLength }
  ) {
    const iv = crypto.randomBytes(ivLength);
    const salt = crypto.randomBytes(saltLength);
    const key = await getScryptKey({ password, salt, keyLength });
    return { key, iv, salt, assocData };
  }

  function encryptStream({ key, iv }, { algorithm, assocData, authTagLength }) {
    return crypto
      .createCipheriv(algorithm, key, iv, {
        authTagLength,
      })
      .setAAD(assocData);
  }

  function encryptChain(
    readable,
    { key, salt, iv },
    { algorithm, assocData, encoding, authTagLength }
  ) {
    const appendIvAndSalt = appendToStream(
      Buffer.concat([iv, salt], iv.length + salt.length)
    );
    const cipher = encryptStream(
      { iv, key },
      { algorithm, assocData, authTagLength }
    );
    return combine(readable.pipe(cipher).pipe(appendIvAndSalt));
  }

  // simulate loading from storage of ciphered data as a stream
  async function getDecryptionParam(
    readable,
    password,
    { assocData, ivLength, saltLength, keyLength }
  ) {
    const { iv, salt } = await new Promise((resolve, reject) => {
      let buffer = Buffer.alloc(0);
      const struct = {
        iv: Buffer.alloc(0),
        salt: Buffer.alloc(0),
        // authTag: Buffer.alloc(0),
      };

      readable.on('error', (error) => {
        reject(error);
      });

      readable.on('data', (data) => {
        while (buffer.length <= ivLength + saltLength) {
          buffer = Buffer.concat([buffer, data], buffer.length + data.length);
        }
        // readable.destroy();
        readable.pause();
        struct.iv = buffer.slice(0, ivLength);
        struct.salt = buffer.slice(ivLength, ivLength + saltLength);
        resolve(struct);
      });
    });

    const key = await getScryptKey({ password, salt, keyLength });
    return { key, iv, salt, assocData };
  }

  function decryptStream(
    { key, iv, authTag },
    { algorithm, assocData, authTagLength }
  ) {
    return crypto
      .createDecipheriv(algorithm, key, iv, {
        authTagLength,
      })
      .setAAD(assocData);
    // // setAuthTag(authTag);
  }

  function decryptChain(
    readable,
    { key, iv },
    { algorithm, assocData, authTagLength, ivLength, saltLength }
  ) {
    const removeIvAndSalt = removeFromStream(ivLength + saltLength);
    const decipher = decryptStream(
      { iv, key },
      { algorithm, assocData, authTagLength }
    );
    return combine(readable.pipe(removeIvAndSalt).pipe(decipher));
  }

  const hrstart = process.hrtime();

  const inputReadable = getReadableStream(input, options.encoding, 16);
  const encryptionParam = await getEncryptionParam(password, options);
  measureExecutionTime(hrstart, 'getEncryptionParam');
  const encryptChainStream = encryptChain(
    inputReadable,
    encryptionParam,
    options
  );
  measureExecutionTime(hrstart, 'encryptChain');

  // simulate storage of ciphered data
  const encryptedData = await new Promise((resolve, reject) => {
    let encryptedData = Buffer.alloc(0);
    encryptChainStream
      .on('error', (error) => {
        reject(error);
      })
      .on('end', () => {
        resolve(encryptedData);
      })
      .on('data', (data) => {
        encryptedData = Buffer.concat(
          [encryptedData, data],
          encryptedData.length + data.length
        );
      });
  });
  measureExecutionTime(hrstart, 'read encryptedData');

  let readable = getReadableStream(encryptedData);

  const decryptionParam = await getDecryptionParam(readable, password, options);
  measureExecutionTime(hrstart, 'getDecryptionParam');

  readable = getReadableStream(encryptedData);
  const decryptChainStream = decryptChain(readable.clone(), decryptionParam, options);
  measureExecutionTime(hrstart, 'decryptChain');

  const decryptedData = await new Promise((resolve, reject) => {
    let decryptedData = Buffer.alloc(0);
    decryptChainStream
      .on('error', (error) => {
        reject(error);
      })
      .on('end', () => {
        resolve(decryptedData);
      })
      .on('data', (data) => {
        decryptedData = Buffer.concat(
          [decryptedData, data],
          decryptedData.length + data.length
        );
      });
  });
  measureExecutionTime(hrstart, 'read decryptedData');

  assert.strictEqual(input.toString('utf8'), decryptedData.toString('utf8'));

  return {
    encryptedText: encryptedData.toString('hex'),
    decryptedText: decryptedData.toString('utf8'),
  };
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
  aes_256_ctr_stream,
  chacha20_poly1305,
  chacha20_poly1305_stream,
  aes_256_cbc_hmac,
};
