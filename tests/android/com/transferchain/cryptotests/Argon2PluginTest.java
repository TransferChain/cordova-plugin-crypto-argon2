package com.transferchain.cryptotests;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Base64;
import androidx.appcompat.app.AppCompatActivity;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.transferchain.argon2.Argon2;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaPreferences;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

@RunWith(AndroidJUnit4.class)
public class Argon2PluginTest {
    private ExecutorService pool;
    private TestCordova cordova;

    @Before public void setUp() {
        pool = Executors.newFixedThreadPool(2);
        cordova = new TestCordova(pool);
    }

    @After public void tearDown() throws Exception {
        pool.shutdown();
        assertTrue("Native work did not finish", pool.awaitTermination(60, TimeUnit.SECONDS));
    }

    private PluginResult call(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        // A stream reuses one plugin instance across create/update/finalize.
        // Cordova initializes that instance once; repeated bootstrap asserts.
        if (plugin.cordova == null) plugin.privateInitialize("test", cordova, null, new CordovaPreferences());
        Capture callback = new Capture();
        assertTrue(plugin.execute(action, args, callback));
        assertTrue("Native callback timed out", callback.done.await(60, TimeUnit.SECONDS));
        assertEquals(1, callback.count);
        return callback.result;
    }

    private PluginResult ok(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        PluginResult result = call(plugin, action, args);
        assertEquals("Native operation rejected", PluginResult.Status.OK.ordinal(), result.getStatus());
        return result;
    }

    private void rejects(CordovaPlugin plugin, String action, JSONArray args, String code) throws Exception {
        PluginResult result = call(plugin, action, args);
        assertEquals(PluginResult.Status.ERROR.ordinal(), result.getStatus());
        JSONObject error = new JSONObject(result.getMessage());
        assertEquals(code, error.getString("code"));
        assertFalse(error.getString("message").isEmpty());
    }

    private static String binary(byte[] data) { return Base64.encodeToString(data, Base64.NO_WRAP); }
    private static byte[] data(PluginResult result) {
        assertEquals(PluginResult.MESSAGE_TYPE_ARRAYBUFFER, result.getMessageType());
        return Base64.decode(result.getMessage(), Base64.DEFAULT);
    }
    private static String hex(byte[] data) {
        StringBuilder out = new StringBuilder();
        for (byte value : data) out.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return out.toString();
    }
    private static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    @Test public void argon2ktAllVariantsAndBounds() throws Exception {
        String[] variants = {"argon2i", "argon2d", "argon2id"};
        String[] expected = {"c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
            "955e5d5b163a1b60bba35fc36d0496474fba4f6b59ad53628666f07fb2f93eaf",
            "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"};
        for (int i = 0; i < variants.length; i++) {
            JSONObject options = new JSONObject().put("variant", variants[i]).put("password", "password")
                .put("time", 2).put("memoryCost", 65536).put("parallelization", 1).put("keyLength", 32);
            assertEquals(expected[i], hex(data(ok(new Argon2(), "derive", new JSONArray().put(options).put("c29tZXNhbHQ=")))));
            options.put("memoryCost", 65537);
            rejects(new Argon2(), "derive", new JSONArray().put(options).put("c29tZXNhbHQ="), "INVALID_ARGUMENT");
        }
    }

    private static class Capture extends CallbackContext {
        final CountDownLatch done = new CountDownLatch(1);
        volatile PluginResult result;
        volatile int count;
        Capture() { super("test", null); }
        @Override public synchronized void sendPluginResult(PluginResult value) {
            result = value;
            count++;
            done.countDown();
        }
    }

    private static class TestCordova implements CordovaInterface {
        final ExecutorService executor;
        TestCordova(ExecutorService executor) { this.executor = executor; }
        @Override public ExecutorService getThreadPool() { return executor; }
        @Override public Context getContext() { return InstrumentationRegistry.getInstrumentation().getTargetContext(); }
        @Override public AppCompatActivity getActivity() { return null; }
        @Override public void startActivityForResult(CordovaPlugin plugin, Intent intent, int code) { throw new UnsupportedOperationException(); }
        @Override public void setActivityResultCallback(CordovaPlugin plugin) { throw new UnsupportedOperationException(); }
        @Override public Object onMessage(String id, Object data) { return null; }
        @Override public void requestPermission(CordovaPlugin plugin, int code, String permission) { throw new UnsupportedOperationException(); }
        @Override public void requestPermissions(CordovaPlugin plugin, int code, String[] permissions) { throw new UnsupportedOperationException(); }
        @Override public boolean hasPermission(String permission) { return true; }
    }
}
