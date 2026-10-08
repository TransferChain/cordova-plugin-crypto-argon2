package com.transferchain.argon2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import com.lambdapioneer.argon2kt.Argon2Kt;
import com.lambdapioneer.argon2kt.Argon2KtResult;
import com.lambdapioneer.argon2kt.Argon2Mode;
import com.lambdapioneer.argon2kt.Argon2Version;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.PluginResult;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public final class Argon2 extends CordovaPlugin {
    // Action names must match the www bridge. Native calculation runs on the
    // Cordova thread pool; each call owns its context and temporary buffers.
    @Override
    // DISPATCH AND CALLBACK PROTOCOL
    // true means the action was recognized, not that calculation succeeded. The
    // outer try/catch handles scheduling failure; the worker's try/catch handles
    // validation and provider failure after dispatch. One accepted request must
    // complete its callback once, with either binary output or a structured error.
    //
    // Cordova's thread pool schedules work; it does not validate input, impose a
    // memory budget, or wipe resources. Call-local ownership avoids shared mutable
    // KDF state. Dropping the JS Promise does not stop an already running native call.
    // UI work requires an explicit activity-thread handoff, never an assumption
    // that a pool thread has UI affinity.
    public boolean execute(String action, JSONArray args, CallbackContext callback) {
        if (!(action.equals("derive"))) return false;

        try {
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
            cordova.getThreadPool().execute(() -> {
                PluginResult result;

                try {
                    if (args.length() != 2 || !(args.opt(0) instanceof JSONObject)) {
                        throw invalid("Expected one options object.");
                    }

                    result = perform(action, new CordovaArgs(args));
                } catch (CryptoFailure error) {
                    result = failure(error.code, error.getMessage());
                } catch (UnsatisfiedLinkError error) {
                    result = failure("NATIVE_UNAVAILABLE", "Argon2 native library could not be loaded.");
                } catch (OutOfMemoryError error) {
                    result = failure("RESOURCE_LIMIT", "Insufficient memory for the crypto operation.");
                } catch (Exception error) {
                    result = failure("OPERATION_FAILED", "Native Argon2 operation failed.");
                }

                callback.sendPluginResult(result);
            });
        } catch (RuntimeException error) {
            fail(callback, "OPERATION_FAILED", "Unable to schedule the crypto operation.");
        }

        return true;
    }

    // Validate native bounds even when the JS bridge has already checked input.
    // Temporary byte arrays registered here are wiped in the finally block.
    static PluginResult perform(String action, CordovaArgs args) throws Exception {
        JSONObject options = args.getJSONObject(0);

        // WHY REQUEST-LOCAL MUTABLE ARRAYS
        // byte[] matches Java crypto APIs and can be overwritten. This ArrayList tracks
        // all temporary arrays needing cleanup, including copies of provider output.
        // Clearing the list would only drop references; finally overwrites the arrays.
        // Java byte is signed but retains all eight bits when mapped to JS Uint8Array.
        //
        // The list belongs to one invocation. No lock is required for this local state;
        // moving it to a static cache would let one request erase another request's key.
        // Immutable password Strings and provider-internal copies are separate ownership
        // boundaries and are not wiped by clearing these arrays.
        List<byte[]> buffers = new ArrayList<>();

        try {
            String variant = string(options, "variant");
            Argon2Mode mode;

            switch (variant) {
                case "argon2i": mode = Argon2Mode.ARGON2_I;
                break;
                case "argon2d": mode = Argon2Mode.ARGON2_D;
                break;
                case "argon2id": mode = Argon2Mode.ARGON2_ID;
                break;
                default: throw invalid("variant must be argon2i, argon2d or argon2id.");
            }

            int time = integer(options, "time", 1, 10);
            int parallelization = integer(options, "parallelization", 1, 4);

            // COST VALIDATION ORDER
            // Validate lane count first because the minimum memory cost depends on it.
            // The native maximum bounds each request, not the combined usage of concurrent
            // requests. parallelization is forwarded into Argon2's algorithm parameters;
            // the application's job concurrency is a separate setting.
            //
            // All costs and the variant must be retained when reproducing a derived key.
            // Do not silently clamp invalid values: the resulting key would differ from
            // the key requested by the caller.
            int memoryCost = integer(options, "memoryCost", 8 * parallelization, 65536);
            int keyLength = integer(options, "keyLength", 4, 1024);

            byte[] password = password(options).getBytes(StandardCharsets.UTF_8);

            buffers.add(password);
            byte[] salt = bytes(args, 1, "salt", 8, 1024, buffers);

            // The JNI API reads direct buffers. Their capacity must match the actual
            // input length because JNI uses capacity, not ByteBuffer position, as length.
            ByteBuffer passwordBuffer = ByteBuffer.allocateDirect(password.length);
            ByteBuffer saltBuffer = null;
            Argon2KtResult result = null;

            try {
                passwordBuffer.put(password);
                saltBuffer = ByteBuffer.allocateDirect(salt.length);
                saltBuffer.put(salt);
                // Preserve the Maven Java/Kotlin API, but load the patched project JNI
                // through SoLoaderShim. Loading the stock .so bypasses the ownership fix.
                result = new Argon2Kt(library -> System.loadLibrary("transferchain_argon2")).hash(mode, passwordBuffer, saltBuffer, time,
                        memoryCost, parallelization, keyLength, Argon2Version.V13);
                // The raw result is the derived key. Encoded output also contains the hash;
                // both native result buffers are wiped in finally, as well as this byte copy.
                byte[] output = result.rawHashAsByteArray();

                buffers.add(output);
                return new PluginResult(PluginResult.Status.OK, output);
            } finally {
                wipe(passwordBuffer);
                wipe(saltBuffer);
                if (result != null) {
                    wipe(result.getRawHash());
                    wipe(result.getEncodedOutput());
                }
            }
        } finally {
            for (byte[] buffer : buffers) Arrays.fill(buffer, (byte) 0);
        }
    }

    // clear() only resets position/limit. Overwrite all bytes afterwards to
    // wipe capacity; reclaiming the allocation remains the JVM's responsibility.
    private static void wipe(ByteBuffer buffer) {
        if (buffer == null) return;

        buffer.clear();
        while (buffer.hasRemaining()) buffer.put((byte) 0);
    }

    private static String password(JSONObject options) throws CryptoFailure {
        String value = string(options, "password");

        if (value.length() > 1024) throw invalid("password exceeds 1024 UTF-16 units.");

        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);

            if (Character.isHighSurrogate(ch)) {
                if (++index >= value.length() || !Character.isLowSurrogate(value.charAt(index))) {
                    throw invalid("password must contain valid Unicode scalar values.");
                }
            } else if (Character.isLowSurrogate(ch)) {
                throw invalid("password must contain valid Unicode scalar values.");
            }
        }

        return value;
    }

    private static int integer(JSONObject options, String name, int min, int max)
            throws CryptoFailure {
        Object value = options.opt(name);

        if (!(value instanceof Number)) throw invalid(name + " must be an integer.");

        // JSON Number does not imply an integer. Reject fractions and non-finite values
        // before casting, so invalid costs cannot be silently rounded or truncated.
        double number = ((Number) value).doubleValue();

        if (!Double.isFinite(number) || number != Math.rint(number) || number < min || number > max) {
            throw invalid(name + " is outside the supported integer range.");
        }

        return (int) number;
    }

    private static String string(JSONObject options, String name) throws CryptoFailure {
        Object value = options.opt(name);

        if (!(value instanceof String)) throw invalid(name + " must be a string.");

        return (String) value;
    }

    private static byte[] bytes(CordovaArgs args, int index, String name, int min, int max,
            List<byte[]> buffers) throws CryptoFailure {
        Object encoded = args.opt(index);

        if (!(encoded instanceof String) || ((String) encoded).length() > 4 * ((max + 2) / 3)) {
            throw invalid(name + " must be an ArrayBuffer within the byte limits.");
        }

        byte[] value;

        try {
            value = args.getArrayBuffer(index);
        } catch (Exception error) {
            throw invalid(name + " must be an ArrayBuffer.");
        }

        buffers.add(value);
        if (value.length < min || value.length > max) {
            throw invalid(name + " is outside the supported byte range.");
        }

        return value;
    }

    private static CryptoFailure invalid(String message) {
        return new CryptoFailure("INVALID_ARGUMENT", message);
    }

    private static final class CryptoFailure extends Exception {
        final String code;

        CryptoFailure(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    private static void fail(CallbackContext callback, String code, String message) {
        callback.sendPluginResult(failure(code, message));
    }

    private static PluginResult failure(String code, String message) {
        JSONObject error = new JSONObject();

        try {
            error.put("code", code);
            error.put("message", message);
            error.put("name", code.equals("INVALID_ARGUMENT") ? "ArgumentError"
                    : code.equals("NATIVE_UNAVAILABLE") ? "RuntimeError" : "OperationError");
        } catch (JSONException impossible) {
            return new PluginResult(PluginResult.Status.ERROR, "Native crypto operation failed.");
        }

        return new PluginResult(PluginResult.Status.ERROR, error);
    }
}
