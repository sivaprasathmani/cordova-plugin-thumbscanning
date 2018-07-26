package cordova.plugin.thumbscanning;

/**
 * Created by sivaprasath_m on 12/21/2017.
 */

import android.Manifest;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.widget.Toast;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;
import org.json.JSONObject;

@TargetApi(Build.VERSION_CODES.M)
public class FingerPrintHelperClass extends FingerprintManager.AuthenticationCallback {

    // You should use the CancellationSignal method whenever your app can no longer process user input, for example when your app goes
    // into the background. If you don’t use this method, then other apps will be unable to access the touch sensor, including the lockscreen!//

    private CancellationSignal cancellationSignal;
    private Context context;
    CallbackContext callBack ;

    public FingerPrintHelperClass(Context mContext) {
        context = mContext;
    }

    //Implement the startAuth method, which is responsible for starting the fingerprint authentication process//

    public void startAuth(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject,CallbackContext callbackContext) {

        callBack = callbackContext;
        cancellationSignal = new CancellationSignal();
        /*if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return;
        }*/

        manager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
    }

    @Override
    //onAuthenticationError is called when a fatal error has occurred. It provides the error code and error message as its parameters//

    public void onAuthenticationError(int errMsgId, CharSequence errString) {

        //I’m going to display the results of fingerprint authentication as a series of toasts.
        //Here, I’m creating the message that’ll be displayed if an error occurs//

        Toast.makeText(context, "Authentication error\n" + errString, Toast.LENGTH_LONG).show();
        PluginResult resultp = new PluginResult(PluginResult.Status.ERROR,"Authentication error");
        // need to keep callback for close event
        resultp.setKeepCallback(true);
        callBack.sendPluginResult(resultp);

    }

    @Override

    //onAuthenticationFailed is called when the fingerprint doesn’t match with any of the fingerprints registered on the device//

    public void onAuthenticationFailed() {
        Toast.makeText(context, "Authentication failed", Toast.LENGTH_LONG).show();
        PluginResult resultp = new PluginResult(PluginResult.Status.ERROR,"Authentication failed");
        // need to keep callback for close event
        resultp.setKeepCallback(true);
        callBack.sendPluginResult(resultp);

    }

    @Override

    //onAuthenticationHelp is called when a non-fatal error has occurred. This method provides additional information about the error,
    //so to provide the user with as much feedback as possible I’m incorporating this information into my toast//
    public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
        Toast.makeText(context, "Authentication help\n" + helpString, Toast.LENGTH_LONG).show();
        PluginResult resultp = new PluginResult(PluginResult.Status.ERROR,"Authentication help");
        // need to keep callback for close event
        resultp.setKeepCallback(true);
        callBack.sendPluginResult(resultp);

    }

    @Override

    //onAuthenticationSucceeded is called when a fingerprint has been successfully matched to one of the fingerprints stored on the user’s device//
    public void onAuthenticationSucceeded(
            FingerprintManager.AuthenticationResult result) {

        Toast.makeText(context, "Success!", Toast.LENGTH_LONG).show();

        PluginResult resultp = new PluginResult(PluginResult.Status.OK,"Success");
        // need to keep callback for close event
        resultp.setKeepCallback(true);
        callBack.sendPluginResult(resultp);
    }

}
