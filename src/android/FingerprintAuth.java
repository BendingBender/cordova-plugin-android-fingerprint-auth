package com.cordova.plugin.android.fingerprintauth;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
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

    KeyguardManager mKeyguardManager;
    FingerprintAuthenticationDialogFragment mFragment;
    public static KeyStore mKeyStore;
    public static KeyGenerator mKeyGenerator;
    public static Cipher mCipherEncryption;
    public static Cipher mCipherDecryption;
    private FingerprintManager mFingerPrintManager;

    public static CallbackContext mCallbackContext;
    public static PluginResult mPluginResult;

    /**
     * Alias for our key in the Android Key Store
     */
    private static String mAppId;

    /**
     * Used to encrypt token
     */
    private static String mPlain;

    /**
     * Used to encrypt token
     */
    private static byte[] mEncrypted;

    /**
     * Initialization vector
     */
    private static byte[] mInitializationVector;

    /**
     * Constructor.
     */
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
            mKeyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize", e);
        }

        try {
            mCipherEncryption = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            mCipherDecryption = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
    }

    /**
     * Executes the request and returns PluginResult.
     *
     * @param action          The action to execute.
     * @param args            JSONArry of arguments for the plugin.
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

            if (isFingerprintAuthAvailable()) {
                createKey();
                cordova.getActivity().runOnUiThread(new Runnable() {
                    public void run() {
                        // Set up the crypto object for later. The object will be authenticated by use
                        // of the fingerprint.
                        if (initCipherEncryption()) {
                            mFragment = new FingerprintAuthenticationDialogFragment(Cipher.ENCRYPT_MODE, description);
                            mFragment.setCancelable(false);
                            // Show the fingerprint dialog. The user has the option to use the fingerprint with
                            // crypto, or you can fall back to using a server-side verified password.
                            mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipherEncryption));
                            mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
                        } else {
                            // This happens if the lock screen has been disabled or or a fingerprint got
                            // enrolled. Thus show the dialog to authenticate with their password first
                            // and ask the user if they want to authenticate with fingerprints in the
                            // future
                            mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipherEncryption));
                            mFragment.setStage(
                                    FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
                            mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
                        }
                    }
                });
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

            if (isFingerprintAuthAvailable()) {
                createKey();
                cordova.getActivity().runOnUiThread(new Runnable() {
                    public void run() {
                        // Set up the crypto object for later. The object will be authenticated by use
                        // of the fingerprint.
                        if (initCipherDecryption(initializationVector)) {
                            mFragment = new FingerprintAuthenticationDialogFragment(Cipher.DECRYPT_MODE, description);
                            mFragment.setCancelable(false);
                            // Show the fingerprint dialog. The user has the option to use the fingerprint with
                            // crypto, or you can fall back to using a server-side verified password.
                            mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipherDecryption));
                            mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
                        } else {
                            // This happens if the lock screen has been disabled or or a fingerprint got
                            // enrolled. Thus show the dialog to authenticate with their password first
                            // and ask the user if they want to authenticate with fingerprints in the
                            // future
                            mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipherDecryption));
                            mFragment.setStage(
                                    FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
                            mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
                        }
                    }
                });
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

    /**
     * Initialize the {@link Cipher} instance with the created key in the
     * {@link #createKey()} method.
     *
     * @return {@code true} if initialization is successful, {@code false} if
     * the lock screen has been disabled or reset after the key was generated,
     * or if a fingerprint got enrolled after the key was generated.
     */
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

    /**
     * Initialize the {@link Cipher} instance with the created key in the
     * {@link #createKey()} method.
     *
     * @return {@code true} if initialization is successful, {@code false} if
     * the lock screen has been disabled or reset after the key was generated,
     * or if a fingerprint got enrolled after the key was generated.
     */
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

    /**
     * Creates a symmetric key in the Android Key Store which can only be used
     * after the user has authenticated with fingerprint.
     */
    public static void createKey() {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            mKeyStore.load(null);
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            mKeyGenerator.init(new KeyGenParameterSpec.Builder(mAppId,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    // Require the user to authenticate with a fingerprint to authorize every use of the key
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
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
            byte[] encrypted = mCipherEncryption.doFinal(mPlain.getBytes());
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
            resultJson.put("plain", plain);
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
