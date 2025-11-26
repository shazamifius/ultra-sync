# Secure P2P File Sync: System Architecture

This document outlines the complete architecture for the decentralized, secure, and high-performance P2P file synchronization system.

## 1. General Architecture & Module Definitions

The system is a set of decoupled Rust crates that collaborate to provide the synchronization service.

*   **`crypto`**: A foundational library for managing user identity (Ed25519 keypairs) with zero-touch, OS-native key protection (DPAPI, Keychain, Secret Service).
*   **`ledger_core`**: Implements the immutable, hash-chained log of all events, using Lamport clocks for causal ordering. It is the single source of truth.
*   **`chunk_engine`**: Handles the physical processing of files using a hybrid strategy: fast fixed-size chunking for binaries and content-defined chunking for text to optimize deduplication.
*   **`sync_engine` (New)**: The central orchestrator. It watches for file changes, coordinates the chunking and hashing process, manages the ledger, and directs the network layer.
*   **`conflict_solver` (New)**: A specialized module that resolves concurrent file edits using a deterministic "first-write-wins" rule based on Lamport timestamps.
*   **`p2p_core`**: The networking layer powered by `libp2p`. It manages peer discovery (DHT, mDNS), secure transport (QUIC + Noise), and the gossiping of ledger entries.
*   **`cli_app`**: A command-line interface for headless operation.
*   **`p2p_ui` (`ui_desktop`)**: The graphical user interface built with Tauri and React.

---

### Architectural Flow Diagrams

#### Flow 1: Local File Change & Broadcast

```text
[User] -> Saves file in [Synced Folder]
   |
   V
[OS File Watcher] -> Notifies change
   |
   V
[sync_engine] -> Receives notification for "my_file.blend"
   |
   1. -> [chunk_engine] -> "Process this file"
   |      |
   |      +--(File is chunked, chunks are hashed, manifest is created)
   |      |
   |      <-- Returns `FileManifest`
   |
   2. -> [crypto] -> "Sign this manifest hash"
   |      |
   |      <-- Returns `Signature`
   |
   3. -> Creates `FileUpdated` event (with manifest, signature, Lamport clock)
   |
   4. -> [ledger_core] -> "Append this event"
   |      |
   |      +--(Event is validated, hash-chained, and saved locally)
   |      |
   |      <-- Returns `NewLedgerEntry`
   |
   5. -> [p2p_core] -> "Broadcast this entry to all peers"
         |
         V
       [Network] -> (Entry is sent to Peer B, C, D...)
```

#### Flow 2: Receiving and Processing a Remote Change

```text
[p2p_core on Peer B] -> Receives `NewLedgerEntry` from network
   |
   V
[sync_engine on Peer B] -> Receives the new entry
   |
   1. -> [ledger_core] -> "Validate and append this remote entry"
   |      |
   |      +--(Signature/hash chain checked. Appended to local ledger.)
   |      |
   |      <-- Returns `ValidationSuccess`
   |
   2. -> Compares the `FileManifest` in the entry with its own local version.
   |
   3. -> [p2p_core] -> "Request chunks [...] from Peer A"
   |
   4. <- [p2p_core] <- Receives chunk data stream from Peer A
   |
   5. -> [chunk_engine] -> "Reassemble file from these chunks"
         |
         V
       (The new version of "my_file.blend" is written to the synced folder)
```

#### Flow 3: Conflict Resolution (Offline Work)

```text
[sync_engine on Peer B] -> Reconnects to network, exchanges ledger heads with Peer A.
   |
   1. -> [ledger_core] -> "Validate entry."
   |      |
   |      +--(Ledger detects that Peer A's entry and Peer B's local entry
   |      |   both point to the same predecessor. This is a fork.)
   |      |
   |      <-- Returns `ForkDetected(entry_A, entry_B)`
   |
   2. -> [conflict_solver] -> "Resolve this conflict"
   |      |
   |      +--(Applies "first-write-wins" rule via Lamport clock. Finds A wins.)
   |      |
   |      <-- Returns `Winner(entry_A)`, `Loser(entry_B)`
   |
   3. -> [sync_engine] -> Executes the resolution plan:
         |
         a. The winning entry's data (A) is fetched and applied.
         b. The losing entry's data (B) is used to create a conflict copy:
            `my_file (conflict from Peer B).blend`
```

---

## 2. Cryptographic Design

*   **Identity:** Ed25519 keypair per user, generated locally. Public key is the `PeerId`.
*   **Key Protection:** Private key is encrypted using OS-native APIs (DPAPI, Keychain, Secret Service) for a zero-touch, passwordless experience.
*   **Transport Security:** All peer communication is end-to-end encrypted and authenticated using `libp2p`'s Noise protocol.
*   **Message Security:** All ledger entries are signed by the author, ensuring integrity and non-repudiation. The hash-chain prevents replay attacks.
*   **Peer Management:** Access is granted via a signed invite code. Peers can be revoked by an Admin via a signed `PeerRevoked` ledger entry, creating a distributed blacklist.

---

## 3. Immutable Ledger and Synchronization Protocol

*   **Ledger Structure:** A log of `SignedEntry` objects, each containing a payload, author, and signature. The `EntryPayload` includes a Lamport clock, the hash of the previous entry, and the specific event (e.g., `FileUpdated`).
*   **Synchronization Protocol:**
    1.  **Gossip:** Small `SignedEntry` objects are gossiped to all peers.
    2.  **Manifests:** The `FileUpdated` entry contains only the hash of a `FileManifest`. The manifest itself (a list of chunk hashes) is fetched separately.
    3.  **Targeted Sync:** Peers compare the new manifest with their local version and request *only* the specific chunks they are missing.
    4.  **Verification:** Every received chunk is hashed and verified against the manifest before being written to disk.

---

## 4. Chunking Engine and Anti-Overwrite System

*   **Hybrid Chunking:**
    *   **Fixed-Size:** Fast, used for binaries and incompressible files.
    *   **Content-Defined (CDC):** Slower but better for deduplication, used for text and source code files.
*   **Anti-Overwrite System (Copy-On-Write):**
    1.  The `sync_engine` watches the filesystem for changes.
    2.  On a completed file save, it snapshots the file, creates a new ledger entry, and broadcasts it.
    3.  If a conflict is detected, the "first-write-wins" rule is applied. The losing version is **not deleted**; it is saved as a separate, clearly-named conflict copy (e.g., `filename (conflict from...).ext`), preventing any data loss.

---

## 5. Threat Analysis and Resilience

*   **Threats Mitigated:**
    *   **Unauthorized Access:** Invite-only + transport encryption.
    *   **Data Tampering:** Signed entries + hashed chunks.
    *   **Peer Impersonation:** Prevented by public key cryptography.
    *   **Sybil Attack:** Limited by invite-only trust model and peer revocation.
    *   **DoS:** Mitigated by rate-limiting and misbehavior penalties.
*   **Resilience:**
    *   **Network Partitions:** The system prioritizes availability. Offline work is seamlessly synced and conflicts are resolved automatically upon reconnection.
    *   **Data Corruption:** A startup integrity check verifies local files against the ledger. Any corrupt file is automatically restored to its last known good state from the network.

---

## 6. Performance Optimizations

*   **Network:** QUIC is used exclusively for its high speed, low latency, and multiplexing capabilities. Peers are selected based on performance heuristics (low RTT, high bandwidth).
*   **Data Pipeline:** File processing (chunking, hashing, compression) is run in a parallel pipeline on multiple CPU cores using `rayon`.
*   **Compression:** LZ4 is used for its extremely fast compression and decompression speeds.
*   **Concurrency:** The entire backend is built on the Tokio async runtime to handle massive I/O concurrency efficiently.

---

## 7. Residual Weak Points & Future Solutions

*   **Unbounded Storage Growth:** The append-only nature of the stores can lead to high disk usage over time.
    *   **Solution:** Implement a garbage collection process for the chunk store and a snapshotting mechanism for the ledger.
*   **Conflict UX for Text Files:** The "conflict copy" method is poor for collaborative text editing.
    *   **Solution:** Enhance the `conflict_solver` to perform a 3-way merge on text-based files, falling back to the conflict-copy method if the merge fails.
*   **Initial Bootstrapping:** Relies on an out-of-band channel (email, chat) to share the first invite code.
    *   **Solution:** Introduce optional, community-run rendezvous servers to allow discovery via temporary, human-readable codes.
*   **Performance with >1M Files:** OS file watchers can become unreliable at extreme scales.
    *   **Solution:** Supplement the real-time watcher with a low-priority background scanner to catch any missed events.