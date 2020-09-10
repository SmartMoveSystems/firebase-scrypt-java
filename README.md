# firebase-scrypt-java
Java implementation of Firebase's custom scrypt implementation, based on [firebase/scrypt](https://github.com/firebase/scrypt).

Usage:

```
// The user's raw text password
String passwd = "user1password";

// Params from the exported account
String salt = "42xEC+ixf3L2lw==";

// Params from the project's password hash parameters
String saltSep = "Bw==";
String signerKey = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
int rounds = 8;
int memcost = 14;

String expectedHash = "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";

assertTrue(FirebaseScrypt.check(passwd, expectedHash, salt, saltSep, signerKey, rounds, memcost));
```
