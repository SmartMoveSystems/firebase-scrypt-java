package com.smartmovesystems.hashcheck;

import com.lambdaworks.crypto.SCrypt;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Java adaptation of https://github.com/firebase/scrypt
 */
public class FirebaseScrypt {

    private static final Logger log = Logger.getLogger(FirebaseScrypt.class.getName());
    private static final Charset CHARSET = StandardCharsets.US_ASCII;
    private static final String CIPHER = "AES/CTR/NoPadding";

    /**
     * Generates the scrypt hash of the user's password using the specified parameneters
     * @param passwd The user's raw password
     * @param salt The salt, base64-encoded
     * @param saltSep The salt separator, base64-encoded
     * @param rounds Scrypt rounds parameter
     * @param memcost Scrypt memost parameter
     * @return Byte array result of Scrypt hash
     * @throws GeneralSecurityException
     */
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
     * @param knownCipherText the known password hash after encryption
     * @param salt the salt, base64-encoded
     * @param saltSep the salt separator, base64-encoded
     * @param signer base64 signer key from firebase project
     * @param rounds rounds scrypt parameter
     * @param memcost memcost scrypt parameter
     * @return True if the hashed, encrypted password matches the known cipertext, false otherwise
     * @throws GeneralSecurityException
     */
    public static boolean check(String passwd, String knownCipherText, String salt, String saltSep, String signer, int rounds, int memcost) throws GeneralSecurityException {
        // hashing password
        byte[] hashedBytes = hashWithSalt(passwd, salt, saltSep, rounds, memcost);

        // encrypting with aes
        byte[] signerBytes = Base64.decodeBase64(signer.getBytes(CHARSET));
        byte[] cipherTextBytes = encrypt(signerBytes, hashedBytes);

        byte[] knownCipherTextBytes = Base64.decodeBase64(knownCipherText.getBytes(CHARSET));

        return Arrays.equals(knownCipherTextBytes, cipherTextBytes);
    }

    private static Key generateKeyFromString(byte[] keyVal) {
        return new SecretKeySpec(keyVal, 0, 32, "AES");
    }

    public static byte[] encrypt(byte[] signer, byte[] derivedKey) {
        try {
            Key key = generateKeyFromString(derivedKey);
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
            Cipher c = Cipher.getInstance(CIPHER);
            c.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            return c.doFinal(signer);
        } catch(Exception ex) {
            log.log(Level.SEVERE, "Error during encryption", ex);
            return null;
        }
    }

    public static byte[] decrypt(byte[] signer, byte[] derivedKey) {
        try {
            Key key = generateKeyFromString(derivedKey);
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
            Cipher c = Cipher.getInstance(CIPHER);
            c.init(Cipher.DECRYPT_MODE, key, ivSpec);
            return c.doFinal(signer);
        } catch(Exception ex) {
            log.log(Level.SEVERE, "Error during decryption", ex);
            return null;
        }
    }
}
