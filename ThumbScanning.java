package cordova.plugin.thumbscanning;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.hardware.fingerprint.FingerprintManager.AuthenticationCallback;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.widget.Toast;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import static android.content.Context.FINGERPRINT_SERVICE;
import static android.content.Context.KEYGUARD_SERVICE;

/**
 * This class echoes a string called from JavaScript.
 */
public class ThumbScanning extends CordovaPlugin {

    // Declare a string variable for the key we’re going to use in our fingerprint authentication
    private static final String KEY_NAME = "yourKey";
    private Cipher cipher;
    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    private FingerprintManager.CryptoObject cryptoObject;
    private FingerprintManager fingerprintManager;
    private KeyguardManager keyguardManager;

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("fingerPrintAuth")) {
            this.fingerPrintAuth(callbackContext);
        } else if (action.equals("checkFingerPrint")) {
            this.checkFingerPrint(callbackContext);
        }
        return true;
    }

    private void checkFingerPrint(CallbackContext callbackContext) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyguardManager =
                    (KeyguardManager) cordova.getActivity().getSystemService(KEYGUARD_SERVICE);
            fingerprintManager =
                    (FingerprintManager) cordova.getActivity().getSystemService(FINGERPRINT_SERVICE);


            //Check whether the device has a fingerprint sensor//
            if (!fingerprintManager.isHardwareDetected()) {
                // If a fingerprint sensor isn’t available, then inform the user that they’ll be unable to use your app’s fingerprint functionality//
                Toast.makeText(cordova.getActivity().getApplicationContext(), "Your device doesn't support fingerprint authentication", Toast.LENGTH_SHORT).show();
                callbackContext.error("Your device doesn't support fingerprint authentication");
            }   //Check that the user has registered at least one fingerprint//
            else if (!fingerprintManager.hasEnrolledFingerprints()) {
                // If the user hasn’t configured any fingerprints, then display the following message//
                Toast.makeText(cordova.getActivity().getApplicationContext(), "No fingerprint configured. Please register at least one fingerprint in your device's Settings", Toast.LENGTH_SHORT).show();
                callbackContext.error("No fingerprint configured. Please register at least one fingerprint in your device's Settings");

            }   //Check that the lockscreen is secured//
            else if (!keyguardManager.isKeyguardSecure()) {
                // If the user hasn’t secured their lockscreen with a PIN password or pattern, then display the following text//
                Toast.makeText(cordova.getActivity().getApplicationContext(), "Please enable lockscreen security in your device's Settings", Toast.LENGTH_SHORT).show();
                callbackContext.error("Please enable lockscreen security in your device's Settings");
            } else {
                callbackContext.success();
            }

        } else {
            callbackContext.error("Android OS should be greater than Marshmallow");
        }

    }

    private void fingerPrintAuth(CallbackContext callbackContext) {
        // If you’ve set your app’s minSdkVersion to anything lower than 23, then you’ll need to verify that the device is running Marshmallow
        // or higher before executing any fingerprint-related code
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            //Get an instance of KeyguardManager and FingerprintManager//
            keyguardManager =
                    (KeyguardManager) cordova.getActivity().getSystemService(KEYGUARD_SERVICE);
            fingerprintManager =
                    (FingerprintManager) cordova.getActivity().getSystemService(FINGERPRINT_SERVICE);
            
            //Check that the lockscreen is secured//
            if (!keyguardManager.isKeyguardSecure()) {
                // If the user hasn’t secured their lockscreen with a PIN password or pattern, then display the following text//
                Toast.makeText(cordova.getActivity().getApplicationContext(), "Please enable lockscreen security in your device's Settings", Toast.LENGTH_SHORT).show();
            } else {
                try {
                    generateKey();
                } catch (FingerprintException e) {
                    e.printStackTrace();
                }

                if (initCipher()) {
                    //If the cipher is initialized successfully, then create a CryptoObject instance//
                    cryptoObject = new FingerprintManager.CryptoObject(cipher);

                    // Here, I’m referencing the FingerprintHandler class that we’ll create in the next section. This class will be responsible
                    // for starting the authentication process (via the startAuth method) and processing the authentication process events//
                    FingerPrintHelperClass helper = new FingerPrintHelperClass(cordova.getActivity().getApplicationContext());
                    helper.startAuth(fingerprintManager, cryptoObject, callbackContext);
                }
            }
        }
    }

    //Create the generateKey method that we’ll use to gain access to the Android keystore and generate the encryption key//

    @TargetApi(Build.VERSION_CODES.M)
    private void generateKey() throws FingerprintException {
        try {
            // Obtain a reference to the Keystore using the standard Android keystore container identifier (“AndroidKeystore”)//
            keyStore = KeyStore.getInstance("AndroidKeyStore");

            //Generate the key//
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            //Initialize an empty KeyStore//
            keyStore.load(null);

            //Initialize the KeyGenerator//
            keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)

                    //Configure this key so that the user has to confirm their identity with a fingerprint each time they want to use it//
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(
                            KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());

            //Generate the key//
            keyGenerator.generateKey();

        } catch (Exception exc) {
            exc.printStackTrace();
            throw new FingerprintException(exc);
        }
    }

    //Create a new method that we’ll use to initialize our cipher//
    @TargetApi(Build.VERSION_CODES.M)
    public boolean initCipher() {
        try {
            //Obtain a cipher instance and configure it with the properties required for fingerprint authentication//
            cipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }

        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME,
                    null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            //Return true if the cipher has been initialized successfully//
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {

            //Return false if cipher initialization failed//
            return false;
        } catch (Exception e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    private class FingerprintException extends Exception {
        public FingerprintException(Exception e) {
            super(e);
        }
    }
}

