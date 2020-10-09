const crypto = require('crypto');
const { simpleHash } = require('./01-simple-hash');
const { simpleHmac } = require('./02-simple-hmac');
const {
  simplepbkdf2,
  nativeScrypt,
  nativeScryptVerify,
  simpleScrypt,
  simpleScryptVerify,
  simpleArgon2,
  simpleArgon2Verify,
} = require('./03-kdf');
const {
  predictableRandom,
  securePseudoRandom,
} = require('./04-random-numbers');
const { diffieHellman } = require('./05-simple-key-exchange');
const {
  aes_256_ctr,
  chacha20_poly1305,
  aes_256_cbc_hmac,
} = require('./06-symmetric-crypto');
const {
  rsa_oaep,
  rsa_kem_native,
  rsa_kem_forge,
} = require('./07-asymmetric-crypto-rsa');
const {
  ed25519_keys,
  ecdh_brainpoolP256r1,
  ecc_crypt_brainpoolP256r1,
  ecc_crypt_brainpoolP256r1_aes_gcm,
} = require('./08-asymmetric-crypto-ecc');

function hash() {
  const shaHash = simpleHash();
  console.log("SHA('hello') =", shaHash.toString('hex'));
}

function hmac() {
  const shaHmac = simpleHmac();
  console.log("SHA-HMAC('cryptography-hello') =", shaHmac.toString('hex'));
}

async function kdfFunctions() {
  let result = await simplepbkdf2();
  console.log("pbkdf2('secret')", result.hash.toString('hex'));

  result = await nativeScrypt();
  // const keyToStore = `$${cost}$${blockSize}$${parallelization}$${salt.toString(
  //   'hex'
  // )}$${hash.toString('hex')}`;
  // TODO
  // let hashIsValid = await nativeScryptVerify();
  console.log("Scrypt('secret')", result.hash.toString('hex'));

  let hashBuffer = await simpleScrypt();
  let hashIsValid = await simpleScryptVerify(hashBuffer.toString('base64'));
  console.log("Scrypt('secret')", hashBuffer.toString('hex'));

  hashBuffer = await simpleArgon2();
  hashIsValid = await simpleArgon2Verify(hashBuffer);
  console.log("Argon2('secret')", hashBuffer.toString('hex'));
}

async function randomNumbersGenerators() {
  let serie = predictableRandom();
  console.log(`pseudo random serie`, {
    seeds: serie.seeds.join(' '),
    results: serie.results.join(' '),
  });

  serie = await securePseudoRandom();
  console.log(`secure pseudo random serie`, {
    seeds: serie.seeds.join(' '),
    results: serie.results.join(' '),
  });
}

function dhKeyExchange() {
  const { aliceSecret, bobSecret } = diffieHellman();
  console.log(`diffieHellman KH()`, {
    aliceSecret: aliceSecret.toString('hex'),
    bobSecret: bobSecret.toString('hex'),
  });
}

async function symmetricCrypto() {
  const ciphers = crypto.getCiphers();
  console.log('available ciphers', ciphers);

  const plainText = 'secretMsg';
  const password = 'p@sSw0rd~123';

  let result = await aes_256_ctr(plainText, password);
  console.log(`aes_256_ctr(${plainText}-${password})`, result);

  result = await chacha20_poly1305(plainText, password);
  console.log(`chacha20_poly1305(${plainText}-${password})`, result);

  result = await aes_256_cbc_hmac(plainText, password);
  console.log(`aes_256_cbc_hmac(${plainText}-${password})`, result);
}

async function asymmetricCryptoRsa() {
  const plainText = 'secretMsg';

  let result = await rsa_oaep(plainText);
  console.log(`rsa_oaep(${plainText})`, result);

  result = await rsa_kem_native(plainText);
  console.log(`rsa_kem_native(${plainText})`, result);

  result = await rsa_kem_forge(plainText);
  console.log(`rsa_kem_forge(${plainText})`, result);
}

async function asymmetricCryptoEc() {
  const curves = crypto.getCurves();
  console.log('available curves', curves);

  const { publicKey, privateKey } = await ed25519_keys();
  console.log(`ed25519_keys()`, { publicKey, privateKey });

  const { aliceSecret, bobSecret } = await ecdh_brainpoolP256r1();
  console.log(`ecdh_brainpoolP256r1()`, {
    aliceSecret: aliceSecret.toString('hex'),
    bobSecret: bobSecret.toString('hex'),
  });

  const plainText = 'secretMsg';

  let result = await ecc_crypt_brainpoolP256r1();
  console.log(`ecc_crypt_brainpoolP256r1()`, result);

  result = await ecc_crypt_brainpoolP256r1_aes_gcm(plainText);
  console.log(`ecc_crypt_brainpoolP256r1_aes_gcm(${plainText})`, result);
}

const COURSES = [
  'HASH',
  'HMAC',
  'KEY DERIVATION FUNCTIONS',
  'RANDOM NUMBERS',
  'KEY EXCHANGE',
  'SYMMETRIC CRYPTO',
  'ASYMMETRIC CRYPTO - RSA',
  'ASYMMETRIC CRYPTO - EC',
];

function checkChapter(chapterOption) {
  const chapter = chapterOption ? Number(chapterOption) : -1;
  if (chapter <= 0) {
    throw new Error(
      `Requires a chapter number as command option (eg : 1, 2, ...)`
    );
  }
  if (isNaN(chapter)) {
    throw new Error(`Chapter must be a number`);
  }
  if (chapter > COURSES.length) {
    throw new Error(`No corresponding exercises for chapter ${chapter}`);
  }
  return chapter;
}

(async function (argv) {
  try {
    const chapter = checkChapter(argv[2]);
    console.log(`Running ${COURSES[chapter - 1]} exercises ...`);

    switch (chapter) {
      case 1:
        hash();
        break;
      case 2:
        hmac();
        break;
      case 3:
        await kdfFunctions();
        break;
      case 4:
        await randomNumbersGenerators();
        break;
      case 5:
        dhKeyExchange();
        break;
      case 6:
        await symmetricCrypto();
        break;
      case 7:
        await asymmetricCryptoRsa();
        break;
      case 8:
        await asymmetricCryptoEc();
        break;
    }
  } catch (error) {
    console.error(error.message);
  }
})(process.argv);
