const cloneable = require('cloneable-readable');
const { Readable, Transform } = require('stream');

function measureExecutionTime(hrstart, fn = '') {
  const hrend = process.hrtime(hrstart);
  console.info(
    `Execution time for ${fn} : %ds %dms`,
    hrend[0],
    hrend[1] / 1000000
  );
}

function getInputBuffer(input, encoding = { input: null }) {
  if (typeof input === 'string') {
    if (typeof encoding.input === 'string') {
      return Buffer.from(input, encoding.input);
    }
    return Buffer.from(input, 'utf8');
  }
  return input;
}

function getReadableStream(input, encoding = null, chunkSize = 32) {
  async function* generate(input, chunkSize) {
    const len = input.length;
    let i = 0;
    while (i < len) {
      yield input.slice(i, (i += chunkSize));
    }
  }

  if (!(input instanceof Readable)) {
    const readable = Readable.from(generate(input, chunkSize));
    return cloneable(readable);
  }
  return cloneable(input);
}

const appendToStream = (value) => {
  let appended = false;

  return new Transform({
    transform(chunk, encoding, callback) {
      if (!appended) {
        this.push(value);
        appended = true;
      }
      this.push(chunk);
      callback();
    },
  });
};

const removeFromStream = (length) => {
  let buffer = Buffer.alloc(0);
  let removed = false;

  return new Transform({
    transform(chunk, encoding, callback) {
      if (!removed || buffer.length <= length) {
        buffer = Buffer.concat([buffer, chunk], buffer.length + chunk.length);
        const partChunk = buffer.slice(length);
        this.push(partChunk);
        removed = true;
      } else {
        this.push(chunk);
      }
      callback();
    },
  });
};

module.exports = {
  measureExecutionTime,
  getInputBuffer,
  getReadableStream,
  appendToStream,
  removeFromStream,
};
