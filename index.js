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
  aes_256_ctr_stream,
  chacha20_poly1305,
  chacha20_poly1305_stream,
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
  ecies_crypto,
  native_ecies_crypto,
} = require('./08-asymmetric-crypto-ecc');
const {
  rsa_signature,
  ec_signature,
  ed25519_signature,
  ed448_signature
} = require('./09-digital-signatures');

function hash() {
  const hashes = crypto.getHashes();
  console.log('available hashes', hashes);

  const shaHash = simpleHash();
  console.log("SHA('hello') =", shaHash.toString('hex'));
}

function hmac() {
  const shaHmac = simpleHmac();
  console.log("SHA-HMAC('cryptography-hello') =", shaHmac.toString('hex'));
}

async function kdfFunctions() {
  const password = 'super_secret';
  let result = await simplepbkdf2();
  console.log(`pbkdf2(${password})`, result.hash.toString('hex'));

  let hashBuffer = await nativeScrypt(password);
  let hashIsValid = await nativeScryptVerify(hashBuffer, password);
  console.log(`Scrypt(${password})`, hashBuffer.toString('hex'), hashIsValid);

  hashBuffer = await simpleScrypt(password);
  hashIsValid = await simpleScryptVerify(
    hashBuffer.toString('base64'),
    password
  );
  console.log(`Scrypt(${password})`, hashBuffer.toString('hex'), hashIsValid);

  hashBuffer = await simpleArgon2(password);
  hashIsValid = await simpleArgon2Verify(hashBuffer, password);
  console.log(`Argon2(${password})`, hashBuffer.toString('hex'), hashIsValid);
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

  const plainText = `"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
  Section 1.10.32 of "de Finibus Bonorum et Malorum", written by Cicero in 45 BC
  
  "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur?"
  1914 translation by H. Rackham
  
  "But I must explain to you how all this mistaken idea of denouncing pleasure and praising pain was born and I will give you a complete account of the system, and expound the actual teachings of the great explorer of the truth, the master-builder of human happiness. No one rejects, dislikes, or avoids pleasure itself, because it is pleasure, but because those who do not know how to pursue pleasure rationally encounter consequences that are extremely painful. Nor again is there anyone who loves or pursues or desires to obtain pain of itself, because it is pain, but because occasionally circumstances occur in which toil and pain can procure him some great pleasure. To take a trivial example, which of us ever undertakes laborious physical exercise, except to obtain some advantage from it? But who has any right to find fault with a man who chooses to enjoy a pleasure that has no annoying consequences, or one who avoids a pain that produces no resultant pleasure?`;
  // const plainText = 'secretMsg';
  const password = 'p@sSw0rd~123';

  let result = await aes_256_ctr(plainText, password);
  console.log(`aes_256_ctr(${password})`, result);

  let stream = aes_256_ctr_stream(plainText, password);
  await new Promise((resolve, reject) => {
    let decipherText = '';
    stream
      .on('error', (error) => {
        reject(error);
      })
      .on('end', () => {
        resolve(decipherText);
      })
      .on('data', (data) => {
        decipherText += data.toString('utf8');
      });
  });

  result = await chacha20_poly1305(plainText, password);
  console.log(`chacha20_poly1305(${password})`, result);

  result = await chacha20_poly1305_stream(plainText, password);
  console.log(`chacha20_poly1305_stream(${password})`, result);

  result = await aes_256_cbc_hmac(plainText, password);
  console.log(`aes_256_cbc_hmac(${password})`, result);
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

  result = ecies_crypto(plainText);
  console.log(`ecies_crypto(${plainText})`, result);

  result = await native_ecies_crypto(plainText);
  console.log(`native_ecies_crypto(${plainText})`, result);
}

async function digitalSignatures() {
  const plainText = 'secretMsg';

  let result = rsa_signature(plainText, {
    modulusLength: 3072,
    alg: 'sha3-512',
  });
  console.log(
    'sha3_512_rsa_signature is valid ?',
    result.signature,
    result.signatureIsValid
  );

  result = ec_signature(plainText, { namedCurve: 'secp256k1', alg: 'sha256' });
  console.log(
    'sha256_secp256k1_signature is valid ?',
    result.signature,
    result.signatureIsValid
  );

  result = ec_signature(plainText, { namedCurve: 'secp521r1', alg: 'sha512' });
  console.log(
    'sha512_secp521r1_signature is valid ?',
    result.signature,
    result.signatureIsValid
  );

  result = ed25519_signature(plainText);
  console.log(
    'ed25519_signature is valid ?',
    result.signature,
    result.signatureIsValid
  );

  result = ed448_signature(plainText);
  console.log(
    'ed448_signature is valid ?',
    result.signature,
    result.signatureIsValid
  );

  
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
  'DIGITAL SIGNATURES',
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
      case 9:
        await digitalSignatures();
        break;
    }
  } catch (error) {
    console.error(error.message);
  }
})(process.argv);
