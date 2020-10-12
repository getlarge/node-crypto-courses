const assert = require('assert');
const argon2 = require('argon2');
const crypto = require('crypto');
const Scrypt = require('scrypt-kdf');
const TextEncoder = require('util').TextEncoder;

// 3 - KEY DERIVATION

// PBKDF2
function simplepbkdf2(password = 'secret', alg = 'sha256', it = 5000) {
  const salt = crypto.randomBytes(16);
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, it, 64, alg, (err, hash) => {
      err ? reject(err) : resolve({ salt, hash, it });
    });
  });
}

// SCRYPT
function nativeScrypt(password = 'secret', params = { logN: 15, r: 8, p: 1 }) {
  // the derived key is 96 bytes: use an ArrayBuffer to view it in different formats
  const buffer = new ArrayBuffer(96);

  const struct = {
    scrypt: new Uint8Array(buffer, 0, 6),
    params: {
      v: new DataView(buffer, 6, 1),
      logN: new DataView(buffer, 7, 1),
      r: new DataView(buffer, 8, 4),
      p: new DataView(buffer, 12, 4),
    },
    salt: new Uint8Array(buffer, 16, 32),
    checksum: new Uint8Array(buffer, 48, 16),
    hmachash: new Uint8Array(buffer, 64, 32),
  };

  struct.scrypt.set(new TextEncoder().encode('scrypt')); 
  struct.params.logN.setUint8(0, params.logN);
  struct.params.r.setUint32(0, params.r, false);
  struct.params.p.setUint32(0, params.p, false);
  struct.salt.set(crypto.randomBytes(32));

  const prefix48 = new Uint8Array(buffer, 0, 48);
  struct.checksum.set(
    crypto.createHash('sha256').update(prefix48).digest().slice(0, 16)
  );

  return new Promise((resolve, reject) => {
    params = {
      N: 2 ** params.logN,
      r: params.r,
      p: params.p,
      maxmem: 2 ** 31 - 1,
    };

    crypto.scrypt(password, struct.salt, 64, params, (err, hmacKey) => {
      if (err) {
        return reject(err);
      }
      const prefix64 = new Uint8Array(buffer, 0, 64);
      const hmacHash = crypto
        .createHmac('sha256', hmacKey.slice(32))
        .update(prefix64)
        .digest();
      struct.hmachash.set(hmacHash);

      resolve(Buffer.from(buffer));
    });
  });
}

function nativeScryptVerify(key, password) {
  const buffer = key.buffer.slice(
    key.byteOffset,
    key.byteOffset + key.byteLength
  );

  const struct = {
    scrypt: new Uint8Array(buffer, 0, 6),
    params: {
      v: new DataView(buffer, 6, 1),
      logN: new DataView(buffer, 7, 1),
      r: new DataView(buffer, 8, 4),
      p: new DataView(buffer, 12, 4),
    },
    salt: new Uint8Array(buffer, 16, 32),
    checksum: new Uint8Array(buffer, 48, 16),
    hmachash: new Uint8Array(buffer, 64, 32),
  };

  const prefix48 = new Uint8Array(buffer, 0, 48);
  const checksum = crypto
    .createHash('sha256')
    .update(prefix48)
    .digest()
    .slice(0, 16);

  if (!crypto.timingSafeEqual(checksum, struct.checksum)) {
    return false;
  }

  return new Promise((resolve, reject) => {
    const params = {
      N: 2 ** struct.params.logN.getUint8(0),
      r: struct.params.r.getUint32(0, false),
      p: struct.params.p.getUint32(0, false),
      maxmem: 2 ** 31 - 1,
    };

    crypto.scrypt(password, struct.salt, 64, params, (err, hmacKey) => {
      if (err) {
        return reject(err);
      }
      const prefix64 = new Uint8Array(buffer, 0, 64);
      const hmacHash = crypto
        .createHmac('sha256', hmacKey.slice(32))
        .update(prefix64)
        .digest();

      assert.strictEqual(
        hmacHash.toString('hex'),
        Buffer.from(struct.hmachash).toString('hex')
      );
      resolve(crypto.timingSafeEqual(hmacHash, struct.hmachash));
    });
  });
}

// OR simpler using scrypt-kdf module
async function simpleScrypt(
  password = 'my secret pw',
  params = { logN: 15, r: 8, p: 1 }
) {
  return Scrypt.kdf(password, params);
}

async function simpleScryptVerify(
  hash,
  password = 'my secret pw',
  params = { logN: 15, r: 8, p: 1 }
) {
  const user = { password: hash };
  const storedKeyBuf = Buffer.from(user.password, 'base64');
  return Scrypt.verify(storedKeyBuf, password, params);
}

// ARGON2
async function simpleArgon2(password = 'secret') {
  return argon2.hash(password);
}

async function simpleArgon2Verify(hash, password = 'secret') {
  return argon2.verify(hash, password);
}

module.exports = {
  simplepbkdf2,
  nativeScrypt,
  nativeScryptVerify,
  simpleScrypt,
  simpleScryptVerify,
  simpleArgon2,
  simpleArgon2Verify,
};
