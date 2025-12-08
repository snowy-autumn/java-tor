# Java Tor
An implementation of the Tor protocol in java

This project is still under development and will likely never adhere to the security standards of the full tor protocol.
It is only meant to be used when access to the tor network is required but privacy is not of utmost importance.

## The state of the project so far

- At the moment there is only a very basic (and probably rather buggy) client.
- It is possible to fetch a microdesc consensus, create and extend circuits and open streams.
- It is possible to connect to v3 hidden services.

Overall, the system is very rigid at the moment and likely isn't able to handle everything that it might encounter.

For example, at the moment, the implementation uses whatever unix time java gives it, instead of using the valid-after time from the consensus. (This is probably not an issue that is likely to occur very often, but it could happen if the system clock is skewed just enough and the client is used just at the right time.) 

---
## Usage on Android
If you're trying to use this implementation on Android, you might have to do these things first:
1. First of all, add BouncyCastle to your `build.gradle.kts` file:
```declarative
implementation("org.bouncycastle:bcprov-jdk15to18:1.81");
```
This version of BouncyCastle should work just fine with this implementation.

2. Then you may need to remove the existing BouncyCastle security provider that is being used by default, since it might not contain the required MessageDigest algorithms, KDF functions, etc..:
```kotlin
// Remove the existing BouncyCastle security provider.
Security.removeProvider("BC")
// Add the current BouncyCastle security provider.
Security.addProvider(BouncyCastleProvider())
```

---

_Note: Since I'm working on a new client at the moment, the previous client has been removed. The current client is not yet complete and probably unstable._

### Third party licenses:
- Bouncy Castle - MIT License
