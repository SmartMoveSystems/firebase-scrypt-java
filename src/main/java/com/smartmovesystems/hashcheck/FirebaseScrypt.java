package com.smartmovesystems.hashcheck;

import com.lambdaworks.crypto.SCrypt;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.ssl.OpenSSL;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;

public class FirebaseScrypt {

    private static final Charset CHARSET = StandardCharsets.UTF_8;

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
     * @param knownCipher the known password hash
     * @param salt the salt
     * @param saltSep the salt separator
     * @param signer base64 signer key from firebase
     * @param rounds rounds scrypt parameter
     * @param memcost memcost scrypt parameter
     * @return
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public static boolean check(String passwd, String knownCipher, String salt, String saltSep, String signer, int rounds, int memcost) throws UnsupportedEncodingException, GeneralSecurityException {
        // hashing password
        byte[] hashedBytes = hashWithSalt(passwd, salt, saltSep, rounds, memcost);
        String derivedKey = new String(Base64.encodeBase64(hashedBytes), CHARSET);

        System.out.println("derivedKey:" + derivedKey);

        // encrypting with aes
        byte[] cipherBytes = encrypt(signer, derivedKey);

        String cipherString = new String(Base64.encodeBase64(cipherBytes), CHARSET);

        System.out.println("cipherString:" + cipherString);

        return knownCipher.equals(cipherString);
    }

    private static Key generateKeyFromString(final String secKey) {
        final byte[] keyVal = Base64.decodeBase64(secKey.getBytes(CHARSET));
        return new SecretKeySpec(keyVal, 0, 32, "AES");
    }


    public static byte[] encrypt(String signer, final String derivedKey) {
        try {
            final Key key = generateKeyFromString(derivedKey);
            final Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key);
            return c.doFinal(signer.getBytes(CHARSET));
        } catch(Exception ex) {
            System.out.println(ex);
            return null;
        }
    }

    public static byte[] decrypt(String signer, final String derivedKey) {

        try {
            final Key key = generateKeyFromString(derivedKey);
            final Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key);
            return c.doFinal(signer.getBytes(CHARSET));
        } catch(Exception ex) {
            System.out.println("The Exception is=" + ex);
            return null;
        }

    }

    public static byte[] encryptOpenSSL(String signer, final String derivedKey) {

        try {
            return OpenSSL.encrypt("aes-256", derivedKey.toCharArray(), signer.getBytes(CHARSET), false, false);
        } catch(Exception ex) {
            System.out.println("The Exception is=" + ex);
            return null;
        }
    }
}
