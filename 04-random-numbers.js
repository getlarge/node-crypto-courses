const crypto = require('crypto');
const readline = require('readline');

// 4 - RANDOM NUMBERS

// PREDICTABLE RANDOM
function predictableRandom(alg = 'sha256') {
  const results = [];
  const seeds = [];
  const min = 10;
  const max = 20;
  const range = 5;
  const startSeed = `${Date.now()}|`;
  seeds.push(startSeed);

  for (let i in Array.from(Array(range).keys())) {
    let nextSeed = `${startSeed}${i}`;
    const hash = crypto
      .createHash(alg)
      .update(nextSeed.toString('ascii'))
      .digest();
    const bigRand = hash.readUInt32BE(0, Buffer.byteLength(hash));
    const rand = min + (bigRand % (max - min + 1));
    seeds.push(nextSeed.toString('ascii'));
    results.push(rand);
  }

  return { seeds, results };
}

// TODO: PSEUDO RANDOM WITH ENTROPY
function pseudoRandomWithEntropy() {
  const range = 30;
  const input = 'hello';
  const results = [];
  let entropy = '';

  for (let i of Array.from(Array(range).keys())) {
    entropy = `${entropy}${input}`;
    // entropy = `${entropy}${input}|${Date.now()}|`;
  }
  const startSeed = crypto
    .createHash('sha256')
    .update(entropy.toString('ascii'))
    .digest();

  for (let i in Array.from(Array(range).keys())) {
    const hash = crypto
      .createHmac('sha256', i)
      .update(startSeed.toString('ascii'))
      .digest();
    const bigRand = hash.readUInt32BE(0, Buffer.byteLength(hash));
    const rand = 1 + (bigRand % 10);
    results.push(rand);
  }

  return results;
}

// SECURE RANDOM
async function securePseudoRandom(
  alg = 'sha256',
  min = 10,
  max = 20,
  range = 5
) {
  const results = [];
  const seeds = [];

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  let entropy = '';

  async function input(question) {
    return new Promise((resolve) => {
      rl.question(question, (s) => {
        resolve(s);
      });
    });
  }

  for (let i of Array.from(Array(range).keys())) {
    const s = await input(`Enter something [${i + 1} of 5]: `);
    entropy = `${entropy}${s}|${Date.now()}|`;
  }
  rl.close();

  const startSeed = crypto
    .createHash(alg)
    .update(entropy.toString('ascii'))
    .digest('hex')
    .slice(2, -1);
  seeds.push(startSeed);

  for (let i in Array.from(Array(5).keys())) {
    let nextSeed = `${startSeed}|${i}`;
    const hash = crypto
      .createHash(alg)
      .update(nextSeed.toString('ascii'))
      .digest();
    seeds.push(hash.toString('hex'));
    const bigRand = hash.readUInt32BE(0, Buffer.byteLength(hash));
    const rand = min + (bigRand % (max - min + 1));
    results.push(rand);
  }

  return { results, seeds };
}

module.exports = {
  predictableRandom,
  pseudoRandomWithEntropy,
  securePseudoRandom,
};
