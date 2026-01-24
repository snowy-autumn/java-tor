# Java Tor
An implementation of the Tor protocol in java

This project is still under development and will likely never adhere to the security standards of the full tor protocol.
It is only meant to be used when access to the tor network is required but privacy is not of utmost importance.

## The state of the project so far

- The client is still in development, but it's definitely mostly functional.
- It is possible to fetch a microdesc consensus, create and extend circuits and open streams.
- It is possible to connect to v3 hidden services.

Overall, the system is working but might not handle everything it encounters.

---
## Usage on Android
If you're trying to use this implementation on Android, you might have to do these things first:
1. First of all, add BouncyCastle to your `build.gradle.kts` file:
```declarative
implementation("org.bouncycastle:bcprov-jdk15to18:1.83");
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
## Example usages
Connect to a regular target:
```java
        // Create a new TorClient object, with the tor-client data being stored in the specified path.
        TorClient torClient = new TorClient("tor-client.data");
        // Initialise the client (Currently requires a tor directory to be specified, behaviour will be changed in the future)
        torClient.initClient(<currently requires a directly to be specified initially>);
        // Attempt to connect to a certain host:port.
        ConnectionInfo connectionInfo = torClient.connect(<destination ip>, <port>);
        // Attempt to send data through the connection.
        connectionInfo.getConnectionIO().write(<bytes>);
        // Receive data from the connection.
        byte[] data = connectionInfo.getConnectionIO().read();
```

Connect to a hidden service:
```java
        // Instantiate a new TorClient object, with the tor-client data being stored in the specified path.
        TorClient torClient = new TorClient("tor-client.data");
        // Initialise the client (Currently requires a directory to be specified, behaviour will be changed in the future)
        torClient.initClient(<currently requires a directly to be specified initially>);
        // Attempt to connect to a certain host:port.
        ConnectionInfo connectionInfo = torClient.connectHS(<onion address>, <port>);
        // Attempt to send data through the connection.
        connectionInfo.getConnectionIO().write(<bytes>);
        // Receive data from the connection.
        byte[] data = connectionInfo.getConnectionIO().read();
```

## Third party licences
- Bouncy Castle - MIT Licence
