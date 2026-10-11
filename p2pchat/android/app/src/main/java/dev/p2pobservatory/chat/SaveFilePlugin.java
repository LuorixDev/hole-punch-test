package dev.p2pobservatory.chat;

import android.app.Activity;
import android.content.Intent;
import android.util.Base64;
import androidx.activity.result.ActivityResult;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.io.OutputStream;

/** User-mediated Storage Access Framework: no broad storage permission or arbitrary path. */
@CapacitorPlugin(name = "P2PSaveFile")
public class SaveFilePlugin extends Plugin {
    private byte[] pending;
    @PluginMethod public synchronized void saveFile(PluginCall call) {
        String url = getBridge().getWebView().getUrl();
        if (!LocalOrigin.isLocalPageUrl(url)) { call.reject("ORIGIN_DENIED"); return; }
        if (pending != null) { call.reject("SAVE_BUSY"); return; }
        String name = call.getString("name", "download.bin");
        String encoded = call.getString("dataB64", "");
        if (name.length() > 255 || encoded.length() > 44739244 || !encoded.matches("[A-Za-z0-9+/]*={0,2}")) { call.reject("INVALID_FILE"); return; }
        try { pending = Base64.decode(encoded, Base64.NO_WRAP); }
        catch (IllegalArgumentException error) { call.reject("INVALID_FILE"); return; }
        if (pending.length > 32 * 1024 * 1024) { pending = null; call.reject("FILE_TOO_LARGE"); return; }
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/octet-stream");
        intent.putExtra(Intent.EXTRA_TITLE, name.replaceAll("[\\\\/\\x00-\\x1f]", "_"));
        startActivityForResult(call, intent, "saved");
    }
    @ActivityCallback private synchronized void saved(PluginCall call, ActivityResult result) {
        byte[] bytes = pending; pending = null;
        if (call == null) return;
        JSObject response = new JSObject();
        if (result.getResultCode() != Activity.RESULT_OK || result.getData() == null || result.getData().getData() == null) {
            response.put("saved", false); response.put("cancelled", true); call.resolve(response); return;
        }
        if (bytes == null) { call.reject("SAVE_INTERRUPTED"); return; }
        try (OutputStream stream = getContext().getContentResolver().openOutputStream(result.getData().getData())) {
            if (stream == null) throw new java.io.IOException();
            stream.write(bytes); response.put("saved", true); response.put("cancelled", false); call.resolve(response);
        } catch (Exception error) { call.reject("SAVE_FAILED"); }
    }
}
