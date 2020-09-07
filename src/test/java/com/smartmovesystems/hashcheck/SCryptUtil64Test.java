package com.smartmovesystems.hashcheck;

import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import static org.junit.Assert.assertTrue;

public class SCryptUtil64Test {

    @Test
    public void knownCiphertextTest() throws UnsupportedEncodingException, GeneralSecurityException {
        String passwd = "user1password";
        String salt = "42xEC+ixf3L2lw==";
        String saltSep = "Bw==";
        String signerKey = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
        int rounds = 8;
        int memcost = 14;

        String expectedHash = "1zRr/0fU8CFiUw2kxLck+k/kQ5MX36IHCy32Vvm+etmf6z7fLuaFdA7mdt2RXPL1qmoGZJT1KVwxhQTyTZaBog==";

        assertTrue(FirebaseScrypt.check(passwd, expectedHash, salt, saltSep, signerKey, rounds, memcost));
    }

}