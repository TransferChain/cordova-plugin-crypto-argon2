import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import com.transferchain.argon2.Argon2;

public final class Argon2Tests {
    private static final ExecutorService POOL = Executors.newFixedThreadPool(2);
    private static int checks;

    private static CallbackContext call(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        plugin.cordova = () -> POOL;
        CallbackContext callback = new CallbackContext();
        if (!plugin.execute(action, args, callback)) throw new AssertionError("Unexpected action rejection");
        if (!callback.done.await(45, TimeUnit.SECONDS)) throw new AssertionError("Native call timeout");
        // The production guard is released in finally after the callback.
        POOL.submit(() -> {}).get();
        return callback;
    }

    private static Object success(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        CallbackContext callback = call(plugin, action, args);
        if (callback.failure != null) throw new AssertionError(callback.failure.toString());
        return callback.result instanceof PluginResult ? ((PluginResult) callback.result).value : callback.result;
    }

    private static void rejected(CordovaPlugin plugin, String action, JSONArray args, String code) throws Exception {
        CallbackContext callback = call(plugin, action, args);
        if (callback.result != null) throw new AssertionError("Rejected operation released output");
        if (!(callback.failure instanceof JSONObject) ||
                !((JSONObject) callback.failure).getString("code").equals(code) ||
                ((JSONObject) callback.failure).getString("message").isBlank()) {
            throw new AssertionError("Expected " + code + ", received " + callback.failure);
        }
        checks++;
    }

    private static String binary(byte[] value) { return Base64.getEncoder().encodeToString(value); }
    private static String hex(byte[] value) { return HexFormat.of().formatHex(value); }
    private static byte[] bytes(String value) { return HexFormat.of().parseHex(value); }
    private static void equal(Object actual, Object expected) {
        if (!actual.equals(expected)) throw new AssertionError("Vector mismatch: " + actual + " != " + expected);
        checks++;
    }

    @SuppressWarnings("unchecked")

    private static void argon2(String reference) throws Exception {
        for (String variant : new String[] {"argon2i", "argon2d", "argon2id"}) {
            for (int lanes : new int[] {1, 2, 4}) {
                for (String password : new String[] {"password", "şifre🔑", ""}) {
                    int memory = lanes == 1 ? 65536 : 8 * lanes + 3;
                    int length = lanes == 4 ? 65 : 32;
                    JSONObject options = new JSONObject().put("variant", variant).put("password", password)
                        .put("time", 2).put("memoryCost", memory).put("parallelization", lanes).put("keyLength", length);
                    byte[] output = (byte[]) success(new Argon2(), "derive",
                        new JSONArray().put(options).put(binary("somesalt".getBytes(StandardCharsets.UTF_8))));
                    Process process = new ProcessBuilder(reference, variant, "2", Integer.toString(memory),
                        Integer.toString(lanes), Integer.toString(length), password).start();
                    String expected = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
                    if (process.waitFor() != 0) throw new AssertionError("C Argon2 reference failed");
                    equal(hex(output), expected);
                }
            }
        }
        JSONObject options = new JSONObject().put("variant", "argon2id").put("password", "password")
            .put("time", 1).put("memoryCost", 32).put("parallelization", 4).put("keyLength", 32);
        for (String field : new String[] {"time", "memoryCost", "parallelization", "keyLength"}) {
            JSONObject bad = new JSONObject(options.toString()).put(field, 0);
            rejected(new Argon2(), "derive", new JSONArray().put(bad).put("c29tZXNhbHQ="), "INVALID_ARGUMENT");
        }
        options.put("memoryCost", 65537);
        rejected(new Argon2(), "derive", new JSONArray().put(options).put("c29tZXNhbHQ="), "INVALID_ARGUMENT");
    }

    public static void main(String[] args) throws Exception {
        try {
            argon2(args[0]);
            System.out.println("PASS: " + checks + " checks");
        } finally { POOL.shutdownNow(); }
    }
}
