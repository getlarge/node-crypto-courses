const assert = require('assert');
const argon2 = require('argon2');
const crypto = require('crypto');
const Scrypt = require('scrypt-kdf');

// 3 - KEY DERIVATION

// PBKDF2
async function simplepbkdf2(alg = 'sha256', msg = 'secret', it = 5000) {
  const salt = crypto.randomBytes(16);
  return new Promise((resolve, reject) => {
    crypto.pbkdf2Sync(msg, salt, it, 64, alg, (err, hash) => {
      err ? reject(err) : resolve({ salt, hash, it });
    });
  });
}

// SCRYPT
function nativeScrypt(
  password = 'secret',
  cost = 16384,
  blockSize = 8,
  parallelization = 1
) {
  const salt = crypto.randomBytes(16);
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      64,
      {
        cost,
        blockSize,
        parallelization,
      },
      (err, hash) => {
        err ? reject(err) : resolve({ salt, hash });
      }
    );
  });
}

function nativeScryptVerify(
  storedKey,
  password,
  salt,
  cost = 16384,
  blockSize = 8,
  parallelization = 1
) {
  // TODO on login
  // let storedKey = '$16384$8$1$salt=$scryptKey';
  // const scryptParam = storedKey.split('$').reduce(
  //   (acc, curr, index) => {
  //     switch (index) {
  //       case 0:
  //         acc.cost = curr;
  //         break;
  //       case 1:
  //         acc.blockSize = curr;
  //         break;
  //       case 2:
  //         acc.parallelization = curr;
  //         break;
  //       case 3:
  //         acc.salt = curr;
  //         break;
  //       case 4:
  //         acc.scryptKey = curr;
  //         break;
  //     }
  //     return acc;
  //   },
  //   { cost, blockSize, parallelization, salt, scryptKey }
  // );

  return new Promise((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      64,
      {
        cost,
        blockSize,
        parallelization,
      },
      (err, hash) => {
        assert.strictEqual(scryptKey.toString('hex'), hash.toString('hex'));
        err
          ? reject(err)
          : resolve(scryptKey.toString('hex') === hash.toString('hex'));
      }
    );
  });
}

// OR simpler using scrypt-kdf module
async function simpleScrypt(
  password = 'my secret pw',
  logN = 15,
  blockSize = 8,
  parallelization = 1
) {
  return Scrypt.kdf(password, {
    logN,
    r: blockSize,
    p: parallelization,
  });
}

async function simpleScryptVerify(
  hash,
  password = 'my secret pw',
  logN = 15,
  blockSize = 8,
  parallelization = 1
) {
  const user = { password: hash };
  const storedKeyBuf = Buffer.from(user.password, 'base64');
  return Scrypt.verify(storedKeyBuf, password, {
    logN,
    r: blockSize,
    p: parallelization,
  });
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
