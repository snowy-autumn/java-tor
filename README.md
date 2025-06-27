# java-tor
An implementation of the Tor protocol in java

This project is still under development and will likely never adhere to the security standards of the full tor protocol.
It is only meant to be used when access to the tor network is required but privacy is not of utmost importance.

Example usage (This is not a great way to do this, it's just the way the client works at the moment):
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