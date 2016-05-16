package com.cordova.plugin.android.fingerprintauth;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.security.KeyStore;
import java.security.KeyStoreException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@TargetApi(23)
public class FingerprintAuth extends CordovaPlugin {

    public static final String TAG = "FingerprintAuth";
    public static String packageName;

    private static final String DIALOG_FRAGMENT_TAG = "FpAuthDialog";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7;

    KeyguardManager mKeyguardManager;
    FingerprintAuthenticationDialogFragment mFragment;
    public static KeyStore mKeyStore;
    public static KeyGenerator mKeyGenerator;
    public static Cipher mCipherEncryption;
    public static Cipher mCipherDecryption;
    private FingerprintManager mFingerPrintManager;

    public static CallbackContext mCallbackContext;
    public static PluginResult mPluginResult;

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
        Log.v(TAG, "Init FingerprintAuth");
        packageName = cordova.getActivity().getApplicationContext().getPackageName();
        mPluginResult = new PluginResult(PluginResult.Status.NO_RESULT);

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
        Log.v(TAG, "FingerprintAuth action: " + action);

        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.e(TAG, "minimum SDK version 23 required");
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            mCallbackContext.error("minimum SDK version 23 required");
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }

        JSONObject arg_object = args.getJSONObject(0);

        if (action.equals("encrypt")) {
            if (!arg_object.has("appId") || !arg_object.has("plain") || !arg_object.has("description")) {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("Missing required parameters");
                mCallbackContext.sendPluginResult(mPluginResult);
                return true;
            }
            mAppId = arg_object.getString("appId");
            mPlain = arg_object.getString("plain");
            final String description = arg_object.getString("description");

            createKey();

            if (isFingerprintAuthAvailable() && initCipherEncryption()) {
                cordova.getActivity().runOnUiThread(new Runnable() {
                    public void run() {
                        mFragment = new FingerprintAuthenticationDialogFragment(Cipher.ENCRYPT_MODE, description);
                        mFragment.setCancelable(false);
                        mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipherEncryption));
                        mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
                    }
                });
                mPluginResult = new  PluginResult(PluginResult.Status.NO_RESULT);
                mPluginResult.setKeepCallback(true);
                mCallbackContext.sendPluginResult(mPluginResult);
            } else {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("Fingerprint authentication not available");
                mCallbackContext.sendPluginResult(mPluginResult);
            }
            return true;
        } else if (action.equals("decrypt")) {
            if (!arg_object.has("appId") || !arg_object.has("encrypted") || !arg_object.has("initializationVector") || !arg_object.has("description")) {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("Missing required parameters");
                mCallbackContext.sendPluginResult(mPluginResult);
                return true;
            }

            mAppId = arg_object.getString("appId");
            mEncrypted = Base64.decode(arg_object.getString("encrypted"), 0);
            final byte[] initializationVector = Base64.decode(arg_object.getString("initializationVector"), 0);
            final String description = arg_object.getString("description");

            if (isFingerprintAuthAvailable() && initCipherDecryption(initializationVector)) {
                cordova.getActivity().runOnUiThread(new Runnable() {
                    public void run() {
                        mFragment = new FingerprintAuthenticationDialogFragment(Cipher.DECRYPT_MODE, description);
                        mFragment.setCancelable(false);
                        mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipherDecryption));
                        mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
                    }
                });
                mPluginResult = new  PluginResult(PluginResult.Status.NO_RESULT);
                mPluginResult.setKeepCallback(true);
                mCallbackContext.sendPluginResult(mPluginResult);
            } else {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("Fingerprint authentication not available");
                mCallbackContext.sendPluginResult(mPluginResult);
            }
            return true;
        } else if (action.equals("availability")) {
            JSONObject resultJson = new JSONObject();
            resultJson.put("isAvailable", isFingerprintAuthAvailable());
            resultJson.put("isHardwareDetected", mFingerPrintManager.isHardwareDetected());
            resultJson.put("hasEnrolledFingerprints", mFingerPrintManager.hasEnrolledFingerprints());
            mPluginResult = new PluginResult(PluginResult.Status.OK);
            mCallbackContext.success(resultJson);
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }
        return false;
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
            return setPluginResultError(e.getMessage());
        }
    }

    private boolean initCipherDecryption(byte[] initializationVector) {
        try {
            mKeyStore.load(null);
            SecretKey key = (SecretKey) mKeyStore.getKey(mAppId, null);
            mCipherDecryption.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initializationVector));
            return true;
        } catch (Exception e) {
            return setPluginResultError(e.getMessage());
        }
    }

    public static void createKey() {
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
        } catch (Exception e) {
            setPluginResultError(e.getMessage());
        }
    }

    public static void onAuthenticatedEncrypt() {
        mPluginResult = new PluginResult(PluginResult.Status.OK);
        JSONObject resultJson = new JSONObject();
        try {
            byte[] encrypted = mCipherEncryption.doFinal(mPlain.getBytes("UTF-8"));
            resultJson.put("result", Base64.encodeToString(encrypted, 0));
            resultJson.put("initializationVector", Base64.encodeToString(mInitializationVector, 0));
        } catch (Exception e) {
            setPluginResultError(e.getMessage());
        }
        mCallbackContext.success(resultJson);
        mCallbackContext.sendPluginResult(mPluginResult);
    }

    public static void onAuthenticatedDecrypt() {
        mPluginResult = new PluginResult(PluginResult.Status.OK);
        JSONObject resultJson = new JSONObject();
        try {
            byte[] plain = mCipherDecryption.doFinal(mEncrypted);
            resultJson.put("plain", new String(plain, "UTF-8"));
        } catch (Exception e) {
            setPluginResultError(e.getMessage());
        }
        mCallbackContext.success(resultJson);
        mCallbackContext.sendPluginResult(mPluginResult);
    }

    public static boolean setPluginResultError(String errorMessage) {
        mCallbackContext.error(errorMessage);
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        return false;
    }

}
