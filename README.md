# Java Tor
An implementation of the Tor protocol in java

This project is still under development and will likely never adhere to the security standards of the full tor protocol.
It is only meant to be used when access to the tor network is required but privacy is not of utmost importance.

## The state of the project so far

- At the moment there is no client, but rather an implementation of the protocol that one could use to create a client.
- It is possible to fetch a microdesc consensus, create and extend circuits and open streams.
- It is possible to connect to v3 hidden services.

Overall, the system is very rigid at the moment and likely isn't able to handle everything that it might encounter.

For example, at the moment, the implementation uses whatever unix time java gives it, instead of using the valid-after time from the consensus. (This is probably not an issue that is likely to occur very often, but it could happen if the system clock is skewed just enough and the client is used just at the right time.) 

---

Example usage of this implementation for creating regular circuits (This is not a great way to do this, it's just the way the implementation works at the moment):
```java
// To connect to a directory.
// Directory authorities can be found in Directories.java
Directory directory = new Directory(directoryHost, directoryPort);
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

Example usage of this implementation for connecting to v3 hidden services:
```java
// Fetch a microdesc consensus and establish a circuit as demonstrated in the previous example.

HiddenService hiddenService = new HiddenService(microdescConsensus, <.onion address>);
HashSet<RouterMicrodesc> potentialHsDirs = hiddenService.possibleFetchDirectories();

// Pick an HSDir at random from potentialHsDirs and attempt to fetch a Hidden Service Descriptor.
HSDirectory hsDirectory = new HSDirectory(microdescConsensus, <Pick an hsDir at random from potentialHsDirs>, circuit);
System.out.println("Extend to HSDir: " + hsDirectory.extendToDirectory());
HiddenServiceDescriptor hsDesc = hsDirectory.fetchHSDescriptor(hiddenService);
// Verify that the descriptor is valid.
System.out.println("Is HS Descriptor Valid: " + hsDesc.isValid());

// We'll open a new circuit we'll call `rendezvousCircuit` to a random OR we'd like to use as our rendezvous point.
// The way to do this is listed in the previous example.
// We'll send attempt to establish a rendezvous.
byte[] rendezvousCookie = rendezvousCircuit.establishRendezvous();
System.out.println("Rendezvous Established: " + (rendezvousCookie != null));

// Now we'll pick a random introduction point from the Hidden Service Descriptor.
IntroductionPoint introductionPoint = hsDesc.getIntroductionPoints().get(<random>);
// We'll then create a new circuit we'll call `introductionCircuit` and extend it up to `introductionPoint`.
System.out.println("Extended to the introduction point: " + introductionCircuit.extend2(introductionPoint));
// Now we'll try to complete the introduction phase by using `introduce1` and checking the received status.
IntroduceAckCommand.IntroduceAckStatus status = introductionCircuit.introduce1(introductionPoint, rendezvousPoint, rendezvousCookie, hiddenService);
System.out.println("Introduction status: " + status);
// We'll then close the introduction circuit.

// Finally, we'll go back to our rendezvous circuit in order to finish the rendezvous.
System.out.println("Rendezvous successful: " + rendezvousCircuit.rendezvous(status.getKeyPair(), introductionPoint));

// If that was successful, then the circuit can now be used just like a regular circuit.
// To open streams to a hidden service, we'll use `openHSStream` instead of `openStream`.
System.out.println("HS stream opened: " + rendezvousCircuit.openHSStream(<random streamId>, destinationHSPort));
rendezvousCircuit.sendData(<streamId>, <data>);
. . .
```