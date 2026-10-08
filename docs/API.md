# Usage and API

All examples run inside an async function after Cordova `deviceready`. They call
the public JavaScript module registered by plugin.xml. Consumer functions such
as consumeKey are placeholders supplied by the caller.

## Interface

`CryptoKit.Argon2.derive(options)` returns Promise<Uint8Array>.

| Field           | Contract                                                      |
| --------------- | ------------------------------------------------------------- |
| password        | Valid Unicode string, up to 1024 UTF-16 units; empty accepted |
| salt            | Uint8Array/ArrayBuffer, 8–1024 bytes                          |
| variant         | argon2i, argon2d or argon2id                                  |
| time            | Integer passes, 1–10                                          |
| memoryCost      | KiB, at least 8 × parallelization, at most 65536              |
| parallelization | Integer lanes, 1–4                                            |
| keyLength       | Integer bytes, 4–1024                                         |

```js
let key
try {
  key = await CryptoKit.Argon2.derive({
    password, salt, variant: 'argon2id', time: 3,
    memoryCost: 65536, parallelization: 4, keyLength: 32
  })
  await consumeKey(key)
} finally {
  key?.fill(0)
}
```

password, salt and consumeKey are supplied by the caller. Lanes are an Argon2
parameter, not a request queue size. Budget memory across concurrent requests.
The string password cannot be reliably zeroed by JavaScript. Android uses
argon2kt; retain applicable dependency notices when distributing it.

## Errors and lifecycle

Handle rejected promises or failure callbacks explicitly. Do not substitute
plaintext, predictable keys or weaker algorithms after failure. Keep caller
buffers valid until async work completes, and wipe only buffers you own.

[Developer guide](../DEVELOPMENT.md) · [Security policy](../SECURITY.md) ·
[README](../README.md)
