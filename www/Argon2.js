const exec = require('cordova/exec')

function invalid(message) {
  return { name: 'ArgumentError', code: 'INVALID_ARGUMENT', message }
}

function optionsObject(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw invalid('Expected an options object.')
  }
}

// Use ArrayBuffer for Cordova binary transport. For a subarray, send only
// its visible range so unrelated bytes in the backing buffer are not exposed.
function buffer(value, name, min, max, optional = false) {
  if (typeof value === 'undefined' && optional) return null

  // WHY Uint8Array / ArrayBuffer
  // Uint8Array provides byte indexing and an exact visible range. ArrayBuffer is
  // its storage and the binary type understood by Cordova. Strings would require
  // an encoding for arbitrary bytes; numeric arrays would need element conversion.
  // Only ordinary ArrayBuffer-backed data is accepted, excluding shared memory.
  //
  // The full-buffer path forwards storage without a snapshot. Callers must avoid
  // mutating input while the asynchronous operation is pending. A partial view is
  // copied to avoid exposing surrounding bytes. This helper does not wipe caller
  // inputs, and Object.freeze on an API does not make input buffers immutable.
  const bytes =
    value instanceof Uint8Array
      ? value
      : value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : null

  if (
    !bytes ||
    !(bytes.buffer instanceof ArrayBuffer) ||
    bytes.byteLength < min ||
    bytes.byteLength > max
  ) {
    throw invalid(
      `${name} must be a Uint8Array or ArrayBuffer within the byte limits.`
    )
  }

  // A view spanning the full buffer can be forwarded without copying. A partial
  // view needs a slice because Cordova receives the ArrayBuffer, not the view's
  // byteOffset/byteLength metadata.
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
    return bytes.buffer
  }

  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  )
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length > 1024) {
    throw invalid('password must be a string of at most 1024 UTF-16 units.')
  }

  for (const character of password) {
    const code = character.codePointAt(0)

    // Iteration is by Unicode code point. A surrogate remaining here is unpaired;
    // reject it before platform encoders can replace it and derive different keys.
    if (code >= 0xd800 && code <= 0xdfff) {
      throw invalid('password must contain valid Unicode scalar values.')
    }
  }
}

// PLUGIN CONTRACT AND REPRODUCIBLE DERIVATION
//
// CryptoKit.Argon2.derive({ password, salt, variant, time, memoryCost,
// parallelization, keyLength }) returns Promise<Uint8Array>. This low-level
// bridge expects the caller to supply costs; application defaults live outside
// this plugin. All three variants are supported: argon2i, argon2d, argon2id.
//
// Units: time is passes (1..10); memoryCost is KiB (8 * parallelization..65,536);
// parallelization is lanes (1..4); keyLength is bytes (4..1,024). Salt contains
// 8..1,024 bytes. For example, memoryCost: 65536 requests 64 MiB of Argon2 memory,
// not 65,536 bytes. Allocation overhead is additional to that algorithm parameter.
//
// Variant, version, costs, salt and output length belong to the derivation
// contract. Preserve them when saving metadata needed to reproduce a key.
// parallelization changes that contract; it is not the shared worker's job limit.
// Keep native validation on both platforms even though JS checks bridge inputs.
module.exports = {
  // Password and numeric options travel as metadata; salt is a separate binary
  // argument. Keep this argument order aligned with the Java/Swift entry points.
  async derive(options) {
    optionsObject(options)

    const { password, variant, time, memoryCost, parallelization, keyLength } =
        options,
      metadata = {
        password,
        variant,
        time,
        memoryCost,
        parallelization,
        keyLength
      },
      salt = buffer(options.salt, 'salt', 8, 1024)

    validatePassword(password)

    return new Promise((resolve, reject) => {
      exec(
        (data) => resolve(new Uint8Array(data)),
        reject,
        'Argon2',
        'derive',
        [metadata, salt]
      )
    })
  }
}
