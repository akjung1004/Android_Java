package com.akjung.android.java;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * 암호화 로직 SingleTon
 */
public class Security {

    private Context mContext;
    private KeyStore mKeyStore;

    private static Security mIntance;

    public static Security getInstance() {
        if (mIntance == null)
            mIntance = new Security();

        return mIntance;
    }


    /**
     * keyStore load
     *
     * @param context
     */

    public void init(Context context) {
        mContext = context;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void loadKeyStore() {
        String keyName = mContext.getPackageName();
        try {
            mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            mKeyStore.load(null);

            // alias : 패키지명
            if (!mKeyStore.containsAlias(keyName)) {
                //새로 키생성
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

                KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyName,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4))
                        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .setDigests(KeyProperties.DIGEST_SHA256,
                                KeyProperties.DIGEST_SHA384,
                                KeyProperties.DIGEST_SHA512)
                        .setUserAuthenticationRequired(false);

                keyPairGenerator.initialize(builder.build());

                keyPairGenerator.generateKeyPair();
            }

        } catch (Exception e) {

        }

    }

    public Signature getSingature() {

        String keyName = mContext.getPackageName();
        try {
            PublicKey publicKey = mKeyStore.getCertificate(keyName).getPublicKey();
            PrivateKey privateKey = (PrivateKey) mKeyStore.getKey(keyName, null);

            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            if (keyPair != null) {
                Signature signature = Signature.getInstance("SHA256withECDSA");
                signature.initSign(keyPair.getPrivate());
                return signature;
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public String encrypt(String plain) {
        loadKeyStore();
        try {
            byte[] bytes = plain.getBytes("UTF-8");
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            //Public Key encrypt
            cipher.init(Cipher.ENCRYPT_MODE, mKeyStore.getCertificate(mContext.getPackageName()).getPublicKey());
            byte[] encryptedBytes = cipher.doFinal(bytes);

            return new String(Base64.encode(encryptedBytes, Base64.DEFAULT));

        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {

        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return null;
    }


    @RequiresApi(api = Build.VERSION_CODES.M)
    public String decrypt(String encryptedText) {
        loadKeyStore();
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            //Private Key로 복호화
            cipher.init(Cipher.DECRYPT_MODE, mKeyStore.getKey(mContext.getPackageName(), null));
            byte[] base64Bytes = encryptedText.getBytes("UTF-8");
            byte[] decryptedBytes = Base64.decode(base64Bytes, Base64.DEFAULT);

            //Log.d(TAG, "Decrypted Text : " + new String(cipher.doFinal(decryptedBytes)));

            return new String(cipher.doFinal(decryptedBytes));

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return null;
    }
}