package com.smartmovesystems.hashcheck;

import com.lambdaworks.crypto.SCrypt;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.ssl.OpenSSL;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

/**
 * Java adaptation of https://github.com/firebase/scrypt
 * Attempts using Java's built-in AES as well as an implementation of OpenSSL's AES
 */
public class FirebaseScrypt {

    private static final Charset CHARSET = StandardCharsets.US_ASCII;

    public static byte[] hashWithSalt(String passwd, String salt, String saltSep, int rounds, int memcost) throws GeneralSecurityException {
        int N = 1 << memcost;
        int p = 1;
        // concatenating decoded salt + separator
        byte[] decodedSaltBytes = Base64.decodeBase64(salt.getBytes(CHARSET));

        byte[] decodedSaltSepBytes = Base64.decodeBase64(saltSep.getBytes(CHARSET));

        byte[] saltConcat = new byte[decodedSaltBytes.length + decodedSaltSepBytes.length];
        System.arraycopy(decodedSaltBytes, 0, saltConcat, 0, decodedSaltBytes.length);
        System.arraycopy(decodedSaltSepBytes, 0, saltConcat, decodedSaltBytes.length, decodedSaltSepBytes.length);

        // hashing password
        return SCrypt.scrypt(passwd.getBytes(CHARSET), saltConcat, N, rounds, p, 64);

    }

    /**
     * Check if the password hashes to the known ciphertext
     * @param passwd the user's password
     * @param knownCipherText the known password hash
     * @param salt the salt
     * @param saltSep the salt separator
     * @param signer base64 signer key from firebase
     * @param rounds rounds scrypt parameter
     * @param memcost memcost scrypt parameter
     * @return
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public static boolean checkWithOpenSSl(String passwd, String knownCipherText, String salt, String saltSep, String signer, int rounds, int memcost) throws UnsupportedEncodingException, GeneralSecurityException {
        // hashing password
        byte[] hashedBytes = hashWithSalt(passwd, salt, saltSep, rounds, memcost);

        System.out.println("derivedKey:" + new String(Base64.encodeBase64(hashedBytes), CHARSET));

        // encrypting with aes
        byte[] signerBytes = Base64.decodeBase64(signer.getBytes(CHARSET));
        byte[] cipherTextBytes = encryptOpenSSL(signerBytes, bytesToChars(hashedBytes));

        byte[] knownCipherBytes = Base64.decodeBase64(knownCipherText.getBytes(CHARSET));

        String cipherTextString = new String(Base64.encodeBase64(cipherTextBytes), CHARSET);

        System.out.println("cipherTextString:" + cipherTextString);

        return Arrays.equals(knownCipherBytes, cipherTextBytes);
    }

    /**
     * Check if the password hashes to the known ciphertext
     * @param passwd the user's password
     * @param knownCipherText the known password hash after encryption
     * @param salt the salt
     * @param saltSep the salt separator
     * @param signer base64 signer key from firebase
     * @param rounds rounds scrypt parameter
     * @param memcost memcost scrypt parameter
     * @return
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public static boolean check(String passwd, String knownCipherText, String salt, String saltSep, String signer, int rounds, int memcost) throws UnsupportedEncodingException, GeneralSecurityException {
        // hashing password
        byte[] hashedBytes = hashWithSalt(passwd, salt, saltSep, rounds, memcost);

        System.out.println("derivedKey:" + new String(Base64.encodeBase64(hashedBytes), CHARSET));

        // encrypting with aes
        byte[] signerBytes = Base64.decodeBase64(signer.getBytes(CHARSET));
        byte[] cipherTextBytes = encrypt(signerBytes, hashedBytes);

        byte[] knownCipherBytes = Base64.decodeBase64(knownCipherText.getBytes(CHARSET));

        String cipherTextString = new String(Base64.encodeBase64(cipherTextBytes), CHARSET);

        System.out.println("cipherTextString:" + cipherTextString);

        return Arrays.equals(knownCipherBytes, cipherTextBytes);
    }

    private static Key generateKeyFromString(final byte[] keyVal) {
        return new SecretKeySpec(keyVal, 0, 32, "AES");
    }

    public static byte[] encrypt(final byte[] signer, final byte[] derivedKey) {
        try {
            final Key key = generateKeyFromString(derivedKey);
            final byte[] nonce = ByteBuffer.allocate(12).putLong(0).array();
            byte[] iv = new byte[16];
            System.arraycopy(nonce, 0, iv, 0, nonce.length);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            final Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            return c.doFinal(signer);
        } catch(Exception ex) {
            System.err.print(ex);
            return null;
        }
    }

    public static byte[] decrypt(final byte[] signer, final byte[] derivedKey) {
        try {
            final Key key = generateKeyFromString(derivedKey);
            final byte[] nonce = ByteBuffer.allocate(8).putLong(0).array();
            byte[] iv = new byte[16];
            System.arraycopy(nonce, 0, iv, 0, nonce.length);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            final Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, ivSpec);
            return c.doFinal(signer);
        } catch(Exception ex) {
            System.err.print(ex);
            return null;
        }
    }

    public static byte[] encryptOpenSSL(byte[] plaintext, char[] pwd) {
        try {
            return OpenSSL.encrypt("aes-256-ctr", pwd, plaintext, false, false);
        } catch(Exception ex) {
            System.err.print(ex);
            return null;
        }
    }

    public static byte[] decryptOpenSSL(byte[] encrypted, final char[] pwd) {
        try {
            return OpenSSL.decrypt("aes-256-ctr", pwd, encrypted);
        } catch(Exception ex) {
            System.err.print(ex);
            return null;
        }
    }

    public static char[] bytesToChars(byte[] byteBuf) {
        char[] charBuf = new char[byteBuf.length];
        for (int i = 0; i < byteBuf.length; i++) {
            charBuf[i] = (char) (byteBuf[i] & 0xff);
        }
        return charBuf;
    }
}
