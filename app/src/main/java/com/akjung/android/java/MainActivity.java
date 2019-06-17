package com.akjung.android.java;

import android.os.Build;
import android.os.Bundle;
import android.support.annotation.RequiresApi;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v4.os.CancellationSignal;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import static android.support.v4.hardware.fingerprint.FingerprintManagerCompat.from;

/**
 * Finger Print Example
 */
public class MainActivity extends AppCompatActivity {

    private FingerprintManagerCompat fingerprintManagerCompat;
    private FingerprintManagerCompat.CryptoObject mCryptoObject;
    private CancellationSignal mCancellationSignal;
    private TextView mInfoTextView;

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mInfoTextView = findViewById(R.id.infoTextView);

        fingerprintManagerCompat = from(this);

        //KeyStore init & load
        Security.getInstance().init(this);
        Security.getInstance().loadKeyStore();

        if(fingerprintManagerCompat.isHardwareDetected() && !fingerprintManagerCompat.hasEnrolledFingerprints()) {
            mInfoTextView.append("지문 없음");
        }
    }

    public void clickFingerPrint(View view) {
        mInfoTextView.setText("fingerPrintStart!!\n");

        mCancellationSignal = new CancellationSignal();
        mCryptoObject = new FingerprintManagerCompat.CryptoObject(Security.getInstance().getSingature());
        fingerprintManagerCompat.authenticate(mCryptoObject , 0, mCancellationSignal, callback, null);
    }

    public void clickFingerPrintCancel(View view) {
        if(mCancellationSignal != null && !mCancellationSignal.isCanceled()) {
            mCancellationSignal.cancel();
        }
    }
    private FingerprintManagerCompat.AuthenticationCallback callback = new FingerprintManagerCompat.AuthenticationCallback(){
        @Override
        public void onAuthenticationError(int errMsgId, CharSequence errString) {
            super.onAuthenticationError(errMsgId, errString);
            Toast.makeText(MainActivity.this, "onAuthenticationError", Toast.LENGTH_SHORT).show();
            mInfoTextView.append("onAuthenticationError!!\n");
        }

        @Override
        public void onAuthenticationHelp(int helpMsgId, final CharSequence helpString) {
            super.onAuthenticationHelp(helpMsgId, helpString);
            mInfoTextView.append(helpString+"\n");
            Toast.makeText(MainActivity.this, "onAuthenticationHelp" + helpString, Toast.LENGTH_SHORT).show();
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            mInfoTextView.append("onAuthenticationSucceeded!!!!!!!!\n");
            Toast.makeText(MainActivity.this, "onAuthenticationSucceeded", Toast.LENGTH_SHORT).show();

        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            mInfoTextView.append("onAuthenticationFailed--------\n");
            Toast.makeText(MainActivity.this, "onAuthenticationFailed", Toast.LENGTH_SHORT).show();
        }
    };
}
