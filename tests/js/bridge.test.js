import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { it as test } from 'mocha'
import vm from 'node:vm'

function bridge(_slug, name, exec) {
  const filename = new URL(`../../www/${name}.js`, import.meta.url),
    module = { exports: {} }

  vm.runInNewContext(readFileSync(filename, 'utf8'), {
    module,
    ArrayBuffer,
    Uint8Array,
    require(id) {
      assert.equal(id, 'cordova/exec')
      return exec
    }
  })
  return module.exports
}

const invalid = { name: 'ArgumentError', code: 'INVALID_ARGUMENT' }

for (const [slug, name] of [['argon2', 'Argon2']]) {
  test(`${name} forwards numeric parameters and salt through the binary bridge`, async () => {
    const salt = new Uint8Array(16),
      options = {
        password: 'şifre🔑',
        salt,
        iterations: 1000,
        hash: 'SHA256',
        variant: 'argon2id',
        time: 2,
        memoryCost: 65536,
        parallelization: 1,
        keyLength: 32
      },
      plugin = bridge(slug, name, (success, _reject, service, action, args) => {
        assert.equal(service, name)
        assert.equal(action, 'derive')
        assert.equal(args.length, 2)
        assert.equal(args[0].keyLength, 32)
        assert.equal(typeof args[0].keyLength, 'number')
        assert.equal(args[0].password, options.password)
        assert.equal('salt' in args[0], false)
        assert.equal(args[1], salt.buffer)
        if (slug === 'pbkdf2') assert.equal(args[0].iterations, 1000)
        else {
          assert.equal(args[0].time, 2)
          assert.equal(args[0].memoryCost, 65536)
          assert.equal(args[0].parallelization, 1)
          assert.equal(args[0].variant, 'argon2id')
        }

        success(new ArrayBuffer(32))
      }),
      result = await plugin.derive(options)

    assert.ok(result instanceof Uint8Array)
    assert.equal(result.byteLength, 32)
  })

  test(`${name} rejects malformed password and binary inputs before calling native`, async () => {
    const plugin = bridge(slug, name, () =>
      assert.fail('Unexpected native call')
    )

    for (const options of [
      null,
      [],
      {},
      { password: 'p', salt: 'c2FsdA==' },
      { password: '\ud800', salt: new Uint8Array(16) },
      { password: 'p'.repeat(1025), salt: new Uint8Array(16) }
    ]) {
      await assert.rejects(plugin.derive(options), invalid)
    }
  })
}
