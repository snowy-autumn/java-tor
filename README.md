# Java Tor
An implementation of the Tor protocol in java

This project is still under development and will likely never adhere to the security standards of the full tor protocol.
It is only meant to be used when access to the tor network is required but privacy is not of utmost importance.

## The state of the project so far

- At the moment there is no client, but rather an implementation of the protocol that one could use to create a client.
- It is possible to fetch a microdesc consensus, create and extend circuits and open streams.
- It is possible to fetch hidden service descriptors.

Overall, the system is very rigid at the moment and likely isn't able to handle everything that it might encounter.

For example, the implementation cannot fetch microdescriptors with the previous shared random value. (This is less of a problem since this implementation is not meant to store the consensus anyway, but it could become one in the future)

---

Example usage (This is not a great way to do this, it's just the way the implementation works at the moment):
```java
// To connect to a directory.
// Directory authorities can be found in Directories.java
Directory directory = new Directory(directoryHost, directoryPort, directoryRSAId);
System.out.println("Directory ready: " + directory.prepareCircuit());
// Fetch the latest microdesc consensus.
MicrodescConsensus microdescConsensus = directory.fetchMicrodescConsensus();
if (microdescConsensus != null) System.out.println("Consensus fetched.");
// Update the circuit used when connecting to the directory with information from the recently fetched consensus.
directory.updateCircuit(microdescConsensus);
// Fetch all the microdescriptors that are present in the microdesc consensus.
directory.fetchMicrodescriptors(microdescConsensus);

// At this point pick 3 nodes from the microdesc consensus in a way that is with accordance to the spec.
// Connect to the guard
Guard guard = new Guard(guardMicrodesc);
System.out.println("Connected: " + guard.connect());
System.out.println("General Tor Handshake: " + guard.generalTorHandshake());
guard.startCellListener();

// Create the circuit.
Circuit circuit = new Circuit(<random circuitId>, guard);
circuit.updateFromConsensus(microdescConsensus);
System.out.println("First hop: " + circuit.create2(guardMicrodesc));
// Extend the circuit.
System.out.println("Second hop: " + circuit.extend2(middleMicrodesc));
System.out.println("Third hop: " + circuit.extend2(exitMicrodesc));

System.out.println("Stream opened: " + circuit.openStream(<random streamId>, destinationHost, destinationPort));
circuit.sendData(<streamId>, <data>);

. . .
```