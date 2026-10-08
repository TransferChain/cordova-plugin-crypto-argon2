import Foundation
import CoreFoundation

#if canImport(Cordova)
import Cordova
#endif

@objc(Argon2)
final class Argon2: CDVPlugin {
    @objc(derive:)
    func derive(_ command: CDVInvokedUrlCommand) {
        run("derive", command)
    }

    // Cordova dispatches this closure to a GCD background queue. There is no
    // shared busy flag; independent calls can run with their own buffers.
    private func run(_ action: String, _ command: CDVInvokedUrlCommand) {
        // EXECUTION AND CALLBACK LIFETIME
        // The Cordova entry point only schedules work; this closure performs validation
        // and derivation. A successful calculation produces one binary result, while a
        // validation/provider failure produces one structured error. Do not send success
        // from a finally/defer block, because that block also runs after failure.
        //
        // All derivation state is local to this request. Independent requests may run
        // concurrently, but the application's shared worker decides how many to submit.
        // Dropping a JS Promise does not cancel a native derivation already in progress;
        // cleanup must complete on the native side before its buffers can be released.
        commandDelegate.run(inBackground: {
            do {
                guard command.arguments.count == 2,
                      let options = command.arguments[0] as? [String: Any] else {
                    throw Self.invalid("Expected one options object.")
                }

                let result = try Self.perform(action, options, command.arguments)

                self.commandDelegate.send(result, callbackId: command.callbackId)
            } catch let error as Failure {
                self.fail(command, error.code, error.message)
            } catch {
                self.fail(command, "OPERATION_FAILED", "Native Argon2 operation failed.")
            }
        })
    }

    // defer cleans up locally owned temporary data on both success and failure.
    // Keep parameter bounds aligned with the www bridge and Android implementation.
    private static func perform(_ action: String, _ options: [String: Any],
                                _ args: [Any]) throws -> CDVPluginResult {
        let variant = try string(options, "variant")
        let type: argon2_type

        switch variant {
        case "argon2i": type = Argon2_i
        case "argon2d": type = Argon2_d
        case "argon2id": type = Argon2_id
        default: throw invalid("variant must be argon2i, argon2d or argon2id.")
        }

        let time = try integer(options, "time", 1, 10)

        // parallelization selects Argon2 lanes and affects the derived key.
        // Never silently replace it with CPU count. memoryCost is measured in KiB.
        let parallelization = try integer(options, "parallelization", 1, 4)
        let memoryCost = try integer(options, "memoryCost", 8 * parallelization, 65536)
        let keyLength = try integer(options, "keyLength", 4, 1024)

        // WHY Data AND SCOPED POINTER BORROWS
        // Data stores the encoded bytes needed by the native provider. var allows
        // resetBytes in defer on both success and failure. UTF-8 byte count differs
        // from String character count, and embedded NUL must remain part of the input.
        //
        // Data has value semantics and may share copy-on-write storage. Local resetBytes
        // is not a promise to erase every bridge/provider copy. withUnsafeBytes pointers
        // are valid only inside their synchronous closures. Do not capture those pointers
        // in asynchronous tasks or return them as handles.
        var password = try Self.password(options)

        defer { password.resetBytes(in: 0..<password.count) }

        var salt = try bytes(args, 1, "salt", 8, 1024)

        defer { salt.resetBytes(in: 0..<salt.count) }

        var output = Data(count: keyLength)

        defer { output.resetBytes(in: 0..<output.count) }

        // Capture byte lengths before borrowing Data storage. The pointers below are
        // valid only inside their closures and must never be retained by async work.
        let passwordLength = password.count
        let saltLength = salt.count

        // TWO LEVELS OF CONCURRENCY
        // GCD allows independent derivations to overlap; reference C may create lane
        // workers inside one call. The synchronous C function finishes that work before
        // returning, so the enclosing Data pointer borrows remain valid.
        // The shared application worker limits jobs, not all internal Argon2 threads.
        // Do not adjust parallelization to match transient CPU load: lanes affect the
        // key derivation contract. New shared scratch buffers would require synchronization;
        // there is no old global BUSY guard protecting such newly shared state.
        let status = password.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                output.withUnsafeMutableBytes { outputBytes in
                    argon2_hash(UInt32(time), UInt32(memoryCost), UInt32(parallelization),
                                passwordBytes.baseAddress, passwordLength,
                                saltBytes.baseAddress, saltLength, outputBytes.baseAddress, keyLength,
                                // Request raw output only; nil/0 disables the optional encoded string.
                                // Version 1.3 and the selected variant must match Android and saved parameters.
                                nil, 0, type, UInt32(ARGON2_VERSION_13.rawValue))
                }
            }
        }

        guard status == ARGON2_OK.rawValue else {
            let code = status == ARGON2_MEMORY_ALLOCATION_ERROR.rawValue ? "RESOURCE_LIMIT" : "OPERATION_FAILED"
            throw Failure(code: code, message: "Native Argon2 operation failed.")
        }

        return CDVPluginResult(status: CDVCommandStatus_OK, messageAsArrayBuffer: output)
    }

    private static func password(_ options: [String: Any]) throws -> Data {
        let value = try string(options, "password")

        guard value.utf16.count <= 1024 else {
            throw invalid("password exceeds 1024 UTF-16 units.")
        }

        return Data(value.utf8)
    }

    private static func integer(_ options: [String: Any], _ name: String,
                                _ min: Int, _ max: Int) throws -> Int {
        guard let value = options[name] as? NSNumber,
              CFGetTypeID(value) != CFBooleanGetTypeID() else {
            throw invalid("\(name) must be an integer.")
        }

        let number = value.doubleValue

        guard number.isFinite, number.rounded(.towardZero) == number,
              number >= Double(min), number <= Double(max) else {
            throw invalid("\(name) is outside the supported integer range.")
        }

        return Int(number)
    }

    private static func string(_ options: [String: Any], _ name: String) throws -> String {
        guard let value = options[name] as? String else {
            throw invalid("\(name) must be a string.")
        }

        return value
    }

    private static func bytes(_ args: [Any], _ index: Int, _ name: String,
                              _ min: Int, _ max: Int) throws -> Data {
        guard let value = args[index] as? Data,
              value.count >= min, value.count <= max else {
            throw invalid("\(name) must be an ArrayBuffer within the byte limits.")
        }

        return value
    }

    private static func invalid(_ message: String) -> Failure {
        return Failure(code: "INVALID_ARGUMENT", message: message)
    }

    private struct Failure: Error {
        let code: String
        let message: String
    }

    private func fail(_ command: CDVInvokedUrlCommand, _ code: String, _ message: String) {
        let error = ["code": code, "message": message,
                     "name": code == "INVALID_ARGUMENT" ? "ArgumentError" : "OperationError"]

        commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_ERROR,
                                            messageAs: error), callbackId: command.callbackId)
    }
}
