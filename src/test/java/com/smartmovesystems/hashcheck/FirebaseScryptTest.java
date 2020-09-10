package com.smartmovesystems.hashcheck;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static com.smartmovesystems.hashcheck.FirebaseScrypt.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class FirebaseScryptTest {

    /**
     * Tests the complete scrypt + AES encryption process for the custom firebase hashing algorithm
     * Uses Java AES CTR
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    @Test
    public void knownCiphertextTest() throws UnsupportedEncodingException, GeneralSecurityException {
        String passwd = "user1password";
        String salt = "42xEC+ixf3L2lw==";
        String saltSep = "Bw==";
        String signerKey = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
        int rounds = 8;
        int memcost = 14;

        String expectedHash = "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";

        assertTrue(FirebaseScrypt.check(passwd, expectedHash, salt, saltSep, signerKey, rounds, memcost));
    }

    /**
     * Tests that the scrypt portion of the algorithm creates the same hash as the C project
     * @throws GeneralSecurityException
     */
    @Test
    public void knownHashTest() throws GeneralSecurityException {
        String passwd = "user1password";
        String salt = "42xEC+ixf3L2lw==";
        String saltSep = "Bw==";
        int rounds = 8;
        int memcost = 14;

        String expectedHash = "6H+iLZtOO+a71BIU8vmPjHi2lL0X4Swrc1AQVKIJnOEf6JZIPGikQ8bPn/io3+Hf4q2qS+bIyht2hmh6JvSIMQ==";

        byte[] scryptedHash = hashWithSalt(passwd, salt, saltSep, rounds, memcost);

        assertEquals(expectedHash, new String(Base64.encodeBase64(scryptedHash)));
    }

    /**
     * Validates basic encryption and decryption with AES CTR
     * @throws GeneralSecurityException
     */
    @Test
    public void encryptDecryptTest() throws GeneralSecurityException {

        String passwd = "user1password";
        String salt = "42xEC+ixf3L2lw==";
        String saltSep = "Bw==";
        String signerKey = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
        int rounds = 8;
        int memcost = 14;

        // hashing password
        byte[] hashedBytes = hashWithSalt(passwd, salt, saltSep, rounds, memcost);
        byte[] signerBytes = Base64.decodeBase64(signerKey.getBytes(StandardCharsets.US_ASCII));
        byte[] cipherBytes = encrypt(signerBytes, hashedBytes);
        byte[] decrypted = decrypt(cipherBytes, hashedBytes);

        assertTrue(Arrays.equals(decrypted, signerBytes));
    }
}