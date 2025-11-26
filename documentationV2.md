# Comprehensive Documentation for p2p_sync_daemon

## 1. Project Overview and Core Concepts

### 1.1. Introduction

The `p2p_sync_daemon` is a peer-to-peer file synchronization application written in Rust. It is designed to provide a secure, transparent, and controlled file-sharing environment. The application enables multiple users to collaborate on a set of files while ensuring the integrity and traceability of every action. This is achieved through an immutable event ledger and role-based access control.

### 1.2. Core Concepts

The application's design is centered around several core concepts that ensure its robustness and reliability:

- **Peer-to-Peer Synchronization Model**: The application operates on a peer-to-peer (P2P) model, where each node in the network is an equal participant. This decentralized architecture eliminates the need for a central server, making the system more resilient and scalable.

- **Gossip and Request-Response Protocols**: The application uses a combination of gossip and request-response protocols for communication. The gossip protocol is used to disseminate information about file updates and lock states to all peers in the network, while the request-response protocol is used for direct peer-to-peer communication, such as requesting specific file blocks.

- **File Manifests for Efficient Transfer**: To transfer large files efficiently, the application uses a file manifest system. A manifest contains metadata about a file, including its size, the hash of each 1 MB chunk, and the total file hash. When a peer wants to download a file, it first requests the manifest and then downloads each chunk individually, verifying the hash of each one.

- **Distributed File Locking**: To prevent conflicts when multiple users try to edit the same file simultaneously, the application implements a distributed file locking mechanism. Before modifying a file, a peer must acquire a lock on it. This lock is then broadcast to all other peers, preventing them from modifying the file until the lock is released.

- **Crash Recovery Mechanism**: The application includes a crash recovery mechanism that ensures data integrity in the event of an unexpected shutdown. This is achieved through a journal that logs all file activity. If the application crashes, it can use the journal to recover any files that were in use and trigger a sync to ensure they are up to date.

## 2. Software Architecture

### 2.1. Component Overview

The `p2p_sync_daemon` is composed of several key components that work together to provide its functionality. The following diagram illustrates the high-level architecture of the application:

```
[File System] <--> [FileWatcher] --> [SyncEngine] <--> [LockManager]
                                     ^
                                     |
                                     v
[Network] <--> [NetworkService] --> [SyncEngine] <--> [JournalService]
```

### 2.2. Component Descriptions

- **`main.rs`**: This is the entry point of the application. It is responsible for initializing all the other components, setting up the communication channels between them, and starting the main event loop.

- **`SyncEngine`**: The `SyncEngine` is the central coordinator of the application. It is responsible for handling events from the `FileWatcher` and the `NetworkService` and taking the appropriate actions. It also manages the file manifests and the `LockManager`.

- **`NetworkService`**: The `NetworkService` is responsible for all peer-to-peer communication. It uses the `libp2p` framework to discover other peers, manage connections, and handle the gossip and request-response protocols.

- **`JournalService`**: The `JournalService` is responsible for the crash recovery mechanism. It logs all file activity to a journal, which can be used to recover any files that were in use in the event of an unexpected shutdown.

- **`LockManager`**: The `LockManager` is responsible for the distributed file locking mechanism. It keeps track of which files are locked by which peers and ensures that no two peers can modify the same file at the same time.

- **`FileWatcher`**: The `FileWatcher` is responsible for monitoring the file system for changes. When a file is modified, it sends an event to the `SyncEngine`, which then takes the appropriate action.

## 3. User Guide

### 3.1. Prerequisites

- **Rust and Cargo**: You will need to have Rust and Cargo installed to compile the application. You can find installation instructions on the [official Rust website](https://www.rust-lang.org/tools/install).

### 3.2. Compilation

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd p2p_sync_daemon
   ```

2. **Build the Application**:
   ```bash
   cargo build --release
   ```
   The executable will be located in `target/release/p2p_sync_daemon`.

### 3.3. Running the Daemon

1. **Start the Daemon**:
   ```bash
   ./target/release/p2p_sync_daemon
   ```

2. **Configure the Synchronization Directory**:
   By default, the application will create a `sync_folder` in the current directory. You can change this by modifying the `sync_dir` variable in `main.rs`.

3. **Connect to Peers**:
   The application uses mDNS to automatically discover other peers on the same local network. If you want to connect to a peer on a different network, you will need to manually configure the connection.

### 3.4. Practical Example

1. **Start the Daemon on Two Machines**:
   Start the daemon on two separate machines on the same local network.

2. **Create a File**:
   On one of the machines, create a new file in the `sync_folder`.

3. **Verify Synchronization**:
   The file should automatically appear in the `sync_folder` on the other machine.

4. **Modify the File**:
   Modify the file on one of the machines. The changes should be automatically synchronized to the other machine.

## 4. API Reference

### 4.1. `journal` Module

- **`JournalService`**: Manages the crash recovery journal.
  - **`new(sync_dir: &Path) -> Result<Self, JournalError>`**: Creates a new `JournalService`.
  - **`log_activity(&self, in_use_paths: &HashSet<PathBuf>) -> Result<(), JournalError>`**: Logs the set of currently active files.
  - **`check_for_recovery(&self) -> Result<HashSet<PathBuf>, JournalError>`**: Checks for a journal file on startup.
  - **`clear(&self) -> Result<(), JournalError>`**: Clears the journal file on a clean shutdown.

### 4.2. `lock` Module

- **`LockManager`**: Manages the state of file locks.
  - **`new(sync_dir: PathBuf) -> Self`**: Creates a new `LockManager`.
  - **`acquire_lock(&mut self, relative_path: &Path) -> Result<GossipMessage, LockError>`**: Attempts to acquire a lock on a file.
  - **`release_lock(&mut self, relative_path: &Path) -> Result<GossipMessage, LockError>`**: Releases a lock on a file.

### 4.3. `network` Module

- **`NetworkService`**: Manages the `libp2p` swarm.
  - **`new(command_receiver: mpsc::Receiver<NetworkCommand>, event_sender: mpsc::Sender<NetworkEvent>) -> Result<Self, Box<dyn std::error::Error>>`**: Creates a new `NetworkService`.
  - **`run(mut self)`**: The main run loop for the network service.

- **`NetworkCommand`**: Enum for commands sent to the network service.
- **`NetworkEvent`**: Enum for events emitted by the network service.

### 4.4. `sync` Module

- **`SyncEngine`**: The central coordinator for file synchronization.
  - **`new(sync_dir: PathBuf, network_command_sender: mpsc::Sender<NetworkCommand>) -> Self`**: Creates a new `SyncEngine`.
  - **`handle_fs_event(&mut self, path: PathBuf)`**: Handles a file system event.
  - **`handle_network_event(&mut self, event: NetworkEvent)`**: Handles a network event.

- **`FileWatcher`**: Watches the file system for changes.
  - **`start(event_sender: mpsc::Sender<FileSystemEvent>, sync_dir: PathBuf) -> notify::Result<()>`**: Starts the file watcher service.
