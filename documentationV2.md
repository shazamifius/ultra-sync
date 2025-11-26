# Secure P2P Application Documentation

## 1. High-Level Architecture Overview

The Secure P2P application is a robust, multi-layered Rust application designed for secure, peer-to-peer file sharing and collaboration. The application is built as a Rust workspace, which is a set of packages (crates) that share a common `Cargo.lock` and output directory. This modular architecture promotes separation of concerns, making the codebase easier to maintain, test, and extend.

The application is composed of the following five crates, each with a distinct responsibility:

- **`crypto`**: This is the foundational layer of the application, responsible for all cryptographic operations. It handles the generation, storage, and management of cryptographic keypairs (using the Ed25519 algorithm), data signing and verification, and SHA-256 hashing. This crate ensures the security and integrity of all data exchanged within the P2P network.

- **`ledger_core`**: This crate implements the immutable, append-only ledger that forms the backbone of the application's data consistency model. Every significant event in the network is recorded as a cryptographically-chained `LogEntry`. This ensures a verifiable and tamper-evident history of all actions, which is crucial for features like role-based access control and file versioning.

- **`p2p_core`**: This is the heart of the application, containing the core P2P networking logic. It is built on top of the `libp2p` framework and is responsible for managing peer connections, handling the request-response protocol for application-specific messages, and orchestrating the interactions between the `crypto` and `ledger_core` crates. It also implements the business logic for features like file locking, role management, and file transfers.

- **`cli_app`**: This crate provides a command-line interface (CLI) for the application. It leverages the `clap` crate to parse command-line arguments and provides a way for users to interact with the P2P network from the terminal. The CLI exposes all the core functionalities of the application, such as starting a peer, connecting to other peers, requesting file locks, and transferring files.

- **`p2p_ui`**: This crate provides a graphical user interface (GUI) for the application, built using the `Tauri` framework. The GUI offers a more user-friendly way to interact with the application, allowing users to perform the same actions as the CLI but with a visual interface. The Tauri backend communicates with the `p2p_core` crate to perform the necessary P2P operations.

The crates are organized in a layered fashion, with the `crypto` and `ledger_core` crates providing the foundational services, the `p2p_core` crate implementing the core logic, and the `cli_app` and `p2p_ui` crates providing the user-facing interfaces. This layered architecture allows for a clean separation of concerns and makes the application more modular and extensible.

## 2. `crypto` Crate

The `crypto` crate serves as the cryptographic foundation for the Secure P2P application. It abstracts away the complexities of key management, digital signatures, and hashing, providing a simple and secure API for other crates in the workspace.

### Key Components

- **`Keypair` struct**: This struct is a container for the cryptographic keys used by a peer. It holds an `ed25519_dalek::SigningKey` and an `ed25519_dalek::VerifyingKey`. The `SigningKey` is the private key used to sign data, while the `VerifyingKey` is the public key used to verify signatures. The `Keypair` can also be converted into a `libp2p::identity::Keypair` for use with the `libp2p` networking stack.

- **`CryptoError` enum**: This enum defines the possible errors that can occur within the `crypto` crate, such as I/O errors, serialization errors, and cryptographic errors from the underlying libraries.

### Core Functionality

- **Key Generation and Management**:
    - `generate_keypair()`: Creates a new `Keypair` using a cryptographically secure random number generator.
    - `save_keypair(keypair, passphrase)`: Saves the `Keypair` to the user's configuration directory. On Windows, it uses the Windows Data Protection API (DPAPI) to encrypt the secret key. On other platforms, it saves the keypair in plaintext (note: the passphrase is not used on non-Windows platforms in the current implementation).
    - `load_keypair(passphrase)`: Loads a previously saved `Keypair` from the configuration directory. It handles decryption on Windows.
    - `keypair_exists()`: Checks if a keypair has already been saved.

- **Digital Signatures**:
    - `sign_data(data, signing_key)`: Signs an arbitrary byte slice (`data`) using the provided `SigningKey` and returns a `Signature`. This is used to prove the authenticity and integrity of messages sent over the network.
    - `verify_signature(data, signature, verifying_key)`: Verifies that a `signature` is valid for the given `data` and `verifying_key`. This is used to authenticate messages received from other peers.

- **Hashing**:
    - `hash_stream<R: Read>(reader)`: Computes the SHA-256 hash of a data stream. This function is designed to be memory-efficient, reading the data in chunks, which makes it suitable for hashing large files without loading them entirely into memory. This is essential for creating file manifests and verifying file integrity during transfers.

## 3. `ledger_core` Crate

The `ledger_core` crate provides the functionality for a secure, immutable, and append-only ledger. This ledger acts as a distributed source of truth for the peers, recording all significant events in a verifiable and tamper-evident manner.

### Key Components

- **`Ledger` struct**: This struct represents the ledger itself. It contains a vector of `LogEntry` items and the path to the file where the ledger is persisted.

- **`LogEntry` struct**: This struct represents a single entry in the ledger. Each entry is composed of:
    - `timestamp`: A UTC timestamp indicating when the event occurred.
    - `peer_id`: The ID of the peer that initiated the event.
    - `event_type`: An enum (`EventType`) that specifies the type of event being recorded.
    - `payload`: A byte vector containing arbitrary data associated with the event.
    - `prev_hash`: The hash of the previous entry in the ledger, which creates the cryptographic chain.
    - `self_hash`: The hash of the current entry, calculated over all other fields.

- **`EventType` enum**: This enum defines all possible events that can be recorded in the ledger, including:
    - `ConnectionEstablished`, `ConnectionLost`, `HeartbeatReceived`: Network-related events.
    - `FileLockRequested`, `LockGranted`, `LockDenied`, `LeaseExpired`: Events related to the file locking mechanism.
    - `FileUpdated`: An event that is recorded when a file is updated, which includes the hash of the new file manifest.
    - `RoleUpdate`: An event that is recorded when a peer's role is changed.

- **`Role` enum**: Defines the possible roles a peer can have: `Reader`, `Contributor`, and `Admin`. This is used for access control.

### Core Functionality

- **Ledger Initialization and Persistence**:
    - `Ledger::load(path)`: Loads an existing ledger from a file or creates a new one if it doesn't exist. If the ledger is new, it automatically creates a "genesis" entry to start the chain.
    - The ledger is persisted to the file system, with each new entry being appended to the end of the file. The data is serialized using `bincode` for a compact binary representation.

- **Appending Entries**:
    - `append_entry(peer_id, event_type, payload)`: Appends a new entry to the ledger. It automatically calculates the hash of the new entry and links it to the previous entry by including the `prev_hash`.

- **Integrity Verification**:
    - `verify_integrity()`: This is a crucial function that iterates through the entire ledger to ensure its integrity. It performs two checks for each entry:
        1. It verifies that the `prev_hash` of the current entry matches the `self_hash` of the previous entry, ensuring the chain is unbroken.
        2. It recalculates the `self_hash` of the current entry to ensure that the entry's data has not been tampered with.
    - This function provides a strong guarantee that the ledger's history has not been altered.

## 4. `p2p_core` Crate

The `p2p_core` crate is the engine of the application, orchestrating all peer-to-peer interactions. It integrates the functionalities of the `crypto` and `ledger_core` crates to provide a secure and consistent networking layer.

### Key Components

- **`MyBehaviour` struct**: This is the main `NetworkBehaviour` for `libp2p`. It bundles two essential protocols:
    - `request_response`: A custom request-response protocol for all application-specific communication. It uses `cbor` for serialization.
    - `identify`: A standard `libp2p` protocol that allows peers to discover each other's public keys and listen addresses.

- **`AppRequest` / `AppResponse` enums**: These enums define the application's request-response protocol. All messages are wrapped in these enums. Key requests include:
    - `Heartbeat`: Periodically sent to other peers to signal presence.
    - `LockRequest`: To request a temporary lock on a file for editing.
    - `RoleUpdateRequest`: To change the role of a peer (admin only).
    - `UpdateFileRequest`: To notify peers of a file update after a lock has been acquired.
    - `ManifestRequest`: To request the `FileManifest` for a file before a transfer.
    - `ChunkRequest`: To request a specific chunk of a file during a transfer.
    - Many of these requests are wrapped in a `SignedPayload` struct, which includes a digital signature to verify the sender's identity and prevent tampering.

- **`RoleRegistry` struct**: This component manages peer roles and permissions. It is initialized by replaying the `RoleUpdate` events from the ledger. It provides helper methods like `is_admin()` to perform access control checks before executing sensitive operations.

- **`FileManifest` struct**: This struct contains metadata about a file, including its total size, a hash of the entire file, and a list of hashes for each 1MB chunk. This is crucial for the file transfer mechanism.

### Core Functionality

- **Server Loop (`run_server`)**: This is the main asynchronous function that drives the P2P node. It uses a `tokio::select!` loop to handle multiple event sources concurrently:
    - **P2P Commands**: It listens for `P2pCommand`s sent from the UI or CLI (e.g., `SetRole`, `UpdateFile`).
    - **Periodic Tasks**: It runs two periodic tasks: sending heartbeats to connected peers and cleaning up expired file leases from the ledger.
    - **`libp2p` Swarm Events**: It processes events from the `libp2p` swarm, such as incoming connections and new messages.

- **Request Handling**: When a peer receives an `AppRequest`, the `handle_inbound_request` function is called. This function verifies the signature of the request (if required) and then delegates to a specific handler based on the request type (e.g., `handle_lock_request`, `handle_chunk_request`).

- **File Locking Mechanism**: The `handle_lock_request` function implements a distributed locking mechanism. Before granting a lock, it performs several checks:
    1.  **Signature Verification**: Ensures the request is from a legitimate peer.
    2.  **Access Control**: Uses the `RoleRegistry` to ensure the peer has the necessary permissions (`Contributor` or `Admin`).
    3.  **Lease Check**: Consults the ledger to see if there is an existing, unexpired lock on the file.
    4.  **Hash Conflict Check**: Compares the hash of the local file with the last known hash from the ledger to prevent conflicts.
    - If all checks pass, a `LockGranted` event is written to the ledger. Otherwise, a `LockDenied` event is recorded.

- **File Transfer Protocol**: The file transfer process is designed to be robust and efficient:
    1.  The receiving peer sends a `ManifestRequest` to the sender.
    2.  The sender creates a `FileManifest` and sends it back in a `ManifestResponse`.
    3.  The receiver thensends a series of `ChunkRequest`s, one for each chunk hash in the manifest.
    4.  The sender responds to each request with a `ChunkResponse`, which contains the signed chunk data.
    5.  The receiver verifies the signature and hash of each chunk before writing it to the file, ensuring the integrity of the transfer.

- **Client-Side Logic (`run_client`)**: The `client.rs` module provides the `run_client` function, which allows the application to run as a transient client for one-off commands (like `RequestLock` or `TransferFile`) without needing to run a persistent server.

## 5. `cli_app` Crate

The `cli_app` crate provides a command-line interface (CLI) for the Secure P2P application. It uses the `clap` crate for parsing command-line arguments and serves as a user-friendly frontend for the `p2p_core` and `ledger_core` functionalities.

### Key Management

The CLI automatically manages the user's cryptographic keypair. The `manage_keypair` function is called at the start of any command that requires a keypair. It checks if a keypair already exists in the configuration directory. If it does, it loads it; otherwise, it generates a new one and saves it.

### Commands

The CLI is structured around a set of subcommands, each corresponding to a specific action.

- **`listen`**: Starts the application in server mode, listening for incoming connections from other peers. This is used to run a persistent node in the network.

- **`dial --remote-addr <ADDRESS>`**: Starts the application in server mode and immediately attempts to connect to a specified peer at `<ADDRESS>`.

- **`ledger [--json]`**: Displays the contents of the local ledger. By default, it prints a human-readable summary of each event. The `--json` flag can be used to output the raw ledger entries in JSON format.

- **`request-lock --file-path <PATH> --peers <PEERS>`**: Runs the application as a client to send a `LockRequest` for the file at `<PATH>` to a list of peers specified by their multiaddresses in `<PEERS>`.

- **`transfer-file --file-path <PATH> --peer-addr <ADDRESS>`**: Runs the application as a client to initiate a file transfer. It requests the file at `<PATH>` from the peer at `<ADDRESS>`.

- **`set-role --peer-id <ID> --role <ROLE> --admin-peer <ADDRESS>`**: Runs as a client to send a `RoleUpdateRequest` to an admin peer at `<ADDRESS>`. This command can only be successfully executed if the peer sending the request is recognized as an admin by the receiving peer.

- **`show-roles`**: Displays the current role assignments by loading the local ledger and reconstructing the `RoleRegistry`.

- **`update-file --file-path <PATH> --peers <PEERS>`**: Runs as a client to send an `UpdateFileRequest` to a list of peers. This should only be used after successfully acquiring a lock on the file.

### Interaction with `p2p_core`

The CLI commands that involve network interaction (`listen`, `dial`, `request-lock`, etc.) are wrappers around the `run_server` and `run_client` functions from the `p2p_core` crate. The CLI parses the command-line arguments, constructs the appropriate command or configuration, and then calls the corresponding function from `p2p_core` to execute the action.

## 6. `p2p_ui` Crate

The `p2p_ui` crate provides a modern, cross-platform graphical user interface (GUI) for the application. It is built with the [Tauri](https://tauri.app/) framework, which allows developers to build applications with web technologies (HTML, CSS, and JavaScript/TypeScript) for the frontend and a Rust-based backend for core logic.

### Architecture

- **Frontend**: The frontend is a standard web application (likely using a framework like React, Vue, or Svelte, though the specifics are not detailed in the backend code) that is responsible for rendering the user interface. It communicates with the Rust backend by invoking "Tauri commands."

- **Backend (`src-tauri`)**: The backend is a Rust application that integrates with the `p2p_core` crate. It is responsible for:
    - **Spawning the P2P Server**: It runs the `p2p_core::run_server` function in a separate `tokio` task, allowing the P2P network operations to run asynchronously without blocking the UI.
    - **State Management**: It uses Tauri's state management to hold a sender half of a `tokio::sync::mpsc::channel`. This channel is used to send `P2pCommand`s from the UI to the running P2P server task.
    - **Exposing Commands**: It uses the `#[tauri::command]` macro to expose Rust functions to the JavaScript frontend. These commands are the bridge between the UI and the core application logic.

### Tauri Commands

The following functions are exposed as Tauri commands and can be called from the frontend:

- **`creer_session(chemin_dossier, passphrase)`**: Creates a new P2P session. It manages the keypair and spawns the `run_server` task in listening mode.
- **`rejoindre_session(remote_addr, passphrase)`**: Joins an existing P2P session by connecting to a remote peer's address. It also manages the keypair and spawns the `run_server` task.
- **`check_keypair_exists()`**: A utility function to check if a keypair already exists, allowing the UI to prompt for a passphrase if needed.
- **`list_files(path)`**: Lists the files in a given directory path.
- **`definir_role(target_peer_id, role)`**: Sends a `P2pCommand::SetRole` to the P2P server task, which will then forward the request to a connected admin peer.
- **`voir_historique()`**: Sends a `P2pCommand::ViewHistory` command to the P2P server, which then emits a `history-updated` event with the ledger data back to the frontend.
- **`voir_roles()`**: Sends a `P2pCommand::ViewRoles` command, which causes the backend to emit a `roles-updated` event with the current role information.
- **`update_file(file_path)`**: Sends a `P2pCommand::UpdateFile` command to initiate a file update.
- **`transfer_file(file_path, target_peer_id)`**: Sends a `P2pCommand::TransferFile` command to request a file from another peer.
- **`get_my_role()`**: A placeholder command to get the current user's role.

## 7. User Guide

### Prerequisites

- **Rust**: Ensure you have the Rust programming language and Cargo installed. You can find instructions at [rustup.rs](https://rustup.rs/).
- **Node.js and npm**: For the Tauri GUI, you will need Node.js and its package manager, npm. You can find instructions at [nodejs.org](https://nodejs.org/).
- **Tauri Prerequisites**: Follow the Tauri setup guide for your specific operating system: [Tauri Prerequisites](https://tauri.app/v1/guides/getting-started/prerequisites).

### Compilation

1.  **Clone the repository**:
    ```bash
    git clone <repository-url>
    cd secure_p2p
    ```

2.  **Compile the CLI application**:
    ```bash
    cargo build --release --package cli_app
    ```
    The compiled binary will be located at `target/release/cli_app`.

3.  **Compile and run the GUI application**:
    ```bash
    cd p2p_ui
    npm install
    npm run tauri dev
    ```
    To build a release version of the GUI, run:
    ```bash
    npm run tauri build
    ```

### Using the CLI

Let's walk through a common scenario with two peers, Peer A and Peer B.

1.  **Peer A starts a session**:
    Peer A will start the application in listening mode. This will generate a keypair if one doesn't exist.
    ```bash
    ./target/release/cli_app listen
    ```
    The application will output its listening address, for example: `Listening on "/ip4/127.0.0.1/tcp/54321"`

2.  **Peer B joins the session**:
    Peer B will use the address from Peer A to connect.
    ```bash
    ./target/release/cli_app dial --remote-addr "/ip4/127.0.0.1/tcp/54321"
    ```

3.  **Peer A (Admin) sets a role for Peer B**:
    - First, Peer A needs to find Peer B's Peer ID. This can be found in the logs when Peer B connects.
    - Let's assume Peer B's ID is `12D3Koo...`. Peer A (who is the first peer and thus the default admin) runs:
    ```bash
    ./target/release/cli_app set-role --peer-id 12D3Koo... --role Contributor --admin-peer "/ip4/127.0.0.1/tcp/54321"
    ```

4.  **Peer B requests a file lock**:
    Now that Peer B is a `Contributor`, they can request a lock on a file.
    ```bash
    ./target/release/cli_app request-lock --file-path "my_document.txt" --peers "/ip4/127.0.0.1/tcp/54321"
    ```

5.  **Peer B updates the file**:
    After getting the lock, Peer B can modify `my_document.txt` locally. Once done, they notify the network of the update.
    ```bash
    ./target/release/cli_app update-file --file-path "my_document.txt" --peers "/ip4/127.0.0.1/tcp/54321"
    ```

6.  **Peer A transfers the updated file**:
    Peer A can now get the updated version of the file from Peer B.
    ```bash
    ./target/release/cli_app transfer-file --file-path "my_document.txt" --peer-addr "/ip4/192.168.1.10/tcp/12345" # Use Peer B's listening address
    ```

### Using the GUI

The GUI provides a more intuitive way to perform the same actions.

1.  **Start the application**: Run `npm run tauri dev` in the `p2p_ui` directory.
2.  **Create or Join a Session**:
    - To start a new session, click "Create Session". This will start a listening peer.
    - To join an existing session, click "Join Session" and enter the multiaddress of the peer you want to connect to.
3.  **Manage Files and Peers**:
    - The main interface will show a list of connected peers and shared files.
    - You can right-click on a peer to manage their role (if you are an admin).
    - You can right-click on a file to request a lock or download the latest version.
    - The UI will provide feedback on the status of your actions (e.g., "Lock granted," "File transfer complete").
4.  **View History and Roles**:
    - The application will have dedicated views to show the ledger history and the current role assignments, which are updated in real-time.
