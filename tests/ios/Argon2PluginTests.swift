import XCTest
import Cordova
import CryptoTestSupport
@testable import NativeCryptoPlugins

final class Argon2PluginTests: XCTestCase {
    private func invoke(_ plugin: CDVPlugin, _ action: String, _ args: [Any],
                        file: StaticString = #filePath, line: UInt = #line) throws -> CDVPluginResult {
        let done = expectation(description: action)
        done.assertForOverFulfill = true
        let delegate = CryptoTestDelegate()
        var captured: CDVPluginResult?
        delegate.onResult = { result in
            captured = result
            done.fulfill()
        }
        plugin.commandDelegate = delegate
        let command = CDVInvokedUrlCommand(arguments: args, callbackId: "test",
                                          className: "test", methodName: action)
        _ = plugin.perform(NSSelectorFromString(action + ":"), with: command)
        wait(for: [done], timeout: 60)
        return try XCTUnwrap(captured, file: file, line: line)
    }

    private func ok(_ plugin: CDVPlugin, _ action: String, _ args: [Any],
                    file: StaticString = #filePath, line: UInt = #line) throws -> CDVPluginResult {
        let result = try invoke(plugin, action, args)
        XCTAssertEqual(result.status.intValue, Int(CDVCommandStatus_OK.rawValue), file: file, line: line)
        return result
    }

    private func rejects(_ plugin: CDVPlugin, _ action: String, _ args: [Any], _ code: String,
                         file: StaticString = #filePath, line: UInt = #line) throws {
        let result = try invoke(plugin, action, args)
        XCTAssertEqual(result.status.intValue, Int(CDVCommandStatus_ERROR.rawValue), file: file, line: line)
        let error = try XCTUnwrap(result.message as? [String: Any])
        XCTAssertEqual(error["code"] as? String, code, file: file, line: line)
        XCTAssertFalse((error["message"] as? String ?? "").isEmpty, file: file, line: line)
    }

    private func binary(_ message: Any?) throws -> Data {
        let value = try XCTUnwrap(message as? [String: Any])
        XCTAssertEqual(value["CDVType"] as? String, "ArrayBuffer")
        let encoded = try XCTUnwrap(value["data"] as? String)
        return try XCTUnwrap(Data(base64Encoded: encoded))
    }

    private func parts(_ result: CDVPluginResult) throws -> [Any] {
        let message = try XCTUnwrap(result.message as? [String: Any])
        XCTAssertEqual(message["CDVType"] as? String, "MultiPart")
        return try XCTUnwrap(message["messages"] as? [Any])
    }

    private func hex(_ bytes: Data) -> String {
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func unhex(_ text: String) -> Data {
        let characters = Array(text)
        return Data(stride(from: 0, to: characters.count, by: 2).map {
            UInt8(String(characters[$0...($0 + 1)]), radix: 16)!
        })
    }

    func testArgon2VariantsAndBounds() throws {
        for (variant, expected) in [
            ("argon2i", "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0"),
            ("argon2d", "955e5d5b163a1b60bba35fc36d0496474fba4f6b59ad53628666f07fb2f93eaf"),
            ("argon2id", "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")
        ] {
            var options: [String: Any] = ["variant": variant, "password": "password", "time": 2,
                                         "memoryCost": 65536, "parallelization": 1, "keyLength": 32]
            let derived = try binary(ok(Argon2(), "derive", [options, Data("somesalt".utf8)]).message)
            XCTAssertEqual(hex(derived), expected)
            options["memoryCost"] = 65537
            try rejects(Argon2(), "derive", [options, Data("somesalt".utf8)], "INVALID_ARGUMENT")
        }
    }

}
