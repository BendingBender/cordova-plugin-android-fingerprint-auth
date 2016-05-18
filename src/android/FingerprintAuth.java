package com.cordova.plugin.android.fingerprintauth;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@TargetApi(23)
public class FingerprintAuth extends CordovaPlugin {

    public static final String TAG = "FingerprintAuth";
    public static String PACKAGE_NAME;

    private static final String DIALOG_FRAGMENT_TAG = "FpAuthDialog";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ALGORITHM = KeyProperties.KEY_ALGORITHM_AES;
    private static final String TRANSFORMATION = KeyProperties.KEY_ALGORITHM_AES
            + "/" + KeyProperties.BLOCK_MODE_CBC
            + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7;

    KeyguardManager mKeyguardManager;
    FingerprintAuthenticationDialogFragment mFragment;
    public static KeyStore mKeyStore;
    public static KeyGenerator mKeyGenerator;
    public static Cipher mCipherEncryption;
    public static Cipher mCipherDecryption;
    private FingerprintManager mFingerPrintManager;

    public static CallbackContext mCallbackContext;

    private static String mAppId;
    private static String mPlain;
    private static byte[] mEncrypted;
    private static byte[] mInitializationVector;

    public FingerprintAuth() {
    }

    /**
     * Sets the context of the Command. This can then be used to do things like
     * get file paths associated with the Activity.
     *
     * @param cordova The context of the main Activity.
     * @param webView The CordovaWebView Cordova is running in.
     */
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);

        PACKAGE_NAME = cordova.getActivity().getApplicationContext().getPackageName();
        if (android.os.Build.VERSION.SDK_INT < 23) {
            return;
        }

        mKeyguardManager = cordova.getActivity().getSystemService(KeyguardManager.class);
        mFingerPrintManager = cordova.getActivity().getApplicationContext()
                .getSystemService(FingerprintManager.class);

        try {
            mKeyGenerator = KeyGenerator.getInstance(ALGORITHM, ANDROID_KEY_STORE);
            mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize", e);
        }

        try {
            mCipherEncryption = Cipher.getInstance(TRANSFORMATION);
            mCipherDecryption = Cipher.getInstance(TRANSFORMATION);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
    }


    /**
     * Executes the request and returns PluginResult.
     *
     * @param action          The action to execute.
     * @param args            JSONArray of arguments for the plugin.
     * @param callbackContext The callback id used when calling back into
     *                        JavaScript.
     * @return A PluginResult object with a status and message.
     */
    public boolean execute(final String action,
                           JSONArray args,
                           CallbackContext callbackContext) throws JSONException {
        mCallbackContext = callbackContext;

        if (android.os.Build.VERSION.SDK_INT < 23) {
            sendResultError("Minimum SDK version 23 required", false);
            return true;
        }

        JSONObject argsObject = args.getJSONObject(0);
        if (action.equals("encrypt")) {
            return encrypt(argsObject);
        } else if (action.equals("decrypt")) {
            return decrypt(argsObject);
        } else if (action.equals("availability")) {
            return isAvailable();
        } else {
            return false;
        }
    }

    private boolean encrypt(JSONObject argsObject) throws JSONException {
        if (!argsObject.has("appId") || !argsObject.has("plain") || !argsObject.has("description")) {
            sendResultError("Missing required parameters", false);
            return true;
        }
        mAppId = argsObject.getString("appId");
        mPlain = argsObject.getString("plain");
        final String description = argsObject.getString("description");

        if (!createKey()) {
            return true;
        }

        if (isFingerprintAuthAvailable() && initCipherEncryption()) {
            cordova.getActivity().runOnUiThread(new Runnable() {
                public void run() {
                    mFragment = new FingerprintAuthenticationDialogFragment();
                    Bundle arguments = new Bundle();
                    arguments.putInt("mode", Cipher.ENCRYPT_MODE);
                    arguments.putString("description", description);
                    mFragment.setArguments(arguments);
                    mFragment.setCancelable(false);
                    mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipherEncryption));
                    mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
                }
            });

            PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
            result.setKeepCallback(true);
            mCallbackContext.sendPluginResult(result);
            return true;
        } else {
            sendResultError("initCipherEncryption failed", true);
            return true;
        }
    }

    private boolean decrypt(JSONObject argsObject) throws JSONException {
        if (!argsObject.has("appId") || !argsObject.has("encrypted") || !argsObject.has("initializationVector") || !argsObject.has("description")) {
            sendResultError("Missing required parameters", false);
            return true;
        }

        mAppId = argsObject.getString("appId");
        mEncrypted = Base64.decode(argsObject.getString("encrypted"), 0);
        final byte[] initializationVector = Base64.decode(argsObject.getString("initializationVector"), 0);
        final String description = argsObject.getString("description");

        if (isFingerprintAuthAvailable() && initCipherDecryption(initializationVector)) {
            cordova.getActivity().runOnUiThread(new Runnable() {
                public void run() {
                    mFragment = new FingerprintAuthenticationDialogFragment();
                    Bundle arguments = new Bundle();
                    arguments.putInt("mode", Cipher.DECRYPT_MODE);
                    arguments.putString("description", description);
                    mFragment.setArguments(arguments);
                    mFragment.setCancelable(false);
                    mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipherDecryption));
                    mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
                }
            });

            PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
            result.setKeepCallback(true);
            mCallbackContext.sendPluginResult(result);
            return true;
        } else {
            sendResultError("initCipherDecryption failed", true);
            return true;
        }
    }

    private boolean isAvailable() throws JSONException {
        JSONObject resultJson = new JSONObject();
        resultJson.put("isAvailable", isFingerprintAuthAvailable());
        resultJson.put("isHardwareDetected", mFingerPrintManager.isHardwareDetected());
        resultJson.put("hasEnrolledFingerprints", mFingerPrintManager.hasEnrolledFingerprints());
        sendResultSuccess(resultJson, false);
        return true;
    }

    private boolean isFingerprintAuthAvailable() {
        return mFingerPrintManager.isHardwareDetected()
                && mFingerPrintManager.hasEnrolledFingerprints();
    }

    private boolean initCipherEncryption() {
        try {
            mKeyStore.load(null);
            SecretKey key = (SecretKey) mKeyStore.getKey(mAppId, null);
            mCipherEncryption.init(Cipher.ENCRYPT_MODE, key);
            IvParameterSpec ivParams = mCipherEncryption.getParameters().getParameterSpec(IvParameterSpec.class);
            mInitializationVector = ivParams.getIV();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean createKey() {
        try {
            mKeyStore.load(null);
            mKeyGenerator.init(new KeyGenParameterSpec.Builder(mAppId,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setRandomizedEncryptionRequired(true)
                    .setUserAuthenticationRequired(true)
                    .build());
            mKeyGenerator.generateKey();
            return true;
        } catch (Exception e) {
            sendResultError(e.getMessage(), true);
            return false;
        }
    }

    private boolean initCipherDecryption(byte[] initializationVector) {
        try {
            mKeyStore.load(null);
            SecretKey key = (SecretKey) mKeyStore.getKey(mAppId, null);
            mCipherDecryption.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initializationVector));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static void onAuthenticatedEncrypt() {
        JSONObject resultJson = new JSONObject();
        try {
            byte[] encrypted = mCipherEncryption.doFinal(mPlain.getBytes("UTF-8"));
            resultJson.put("result", Base64.encodeToString(encrypted, 0));
            resultJson.put("initializationVector", Base64.encodeToString(mInitializationVector, 0));
        } catch (Exception e) {
            sendResultError(e.getMessage(), true);
            return;
        }
        sendResultSuccess(resultJson, false);
    }

    public static void onAuthenticatedDecrypt() {
        JSONObject resultJson = new JSONObject();
        try {
            byte[] plain = mCipherDecryption.doFinal(mEncrypted);
            resultJson.put("plain", new String(plain, "UTF-8"));
        } catch (Exception e) {
            sendResultError(e.getMessage(), true);
            return;
        }
        sendResultSuccess(resultJson, false);
    }

    public static void onCancel() {
        JSONObject resultJson = new JSONObject();
        try {
            resultJson.put("userCanceled", true);
        } catch (Exception e) {
            sendResultError(e.getMessage(), true);
            return;
        }
        sendResultSuccess(resultJson, false);
    }

    private static void sendResultSuccess(JSONObject resultJson, boolean keepCallback) {
        PluginResult result = new PluginResult(PluginResult.Status.OK);
        result.setKeepCallback(keepCallback);
        mCallbackContext.success(resultJson);
        mCallbackContext.sendPluginResult(result);
    }

    private static void sendResultError(String message, boolean keepCallback) {
        PluginResult result = new PluginResult(PluginResult.Status.ERROR);
        result.setKeepCallback(keepCallback);
        mCallbackContext.error(message);
        mCallbackContext.sendPluginResult(result);
    }

}
