# Secure P2P - Système de Fichiers Distribué et Sécurisé

Ce projet implémente un système de fichiers distribué, sécurisé et versionné en Rust, basé sur une architecture pair-à-pair (P2P). Il permet à un groupe de pairs de collaborer sur un ensemble de fichiers de manière sécurisée, en prévenant les conflits d'édition et en garantissant l'intégrité et l'authenticité des données et des actions.

## 1. Concepts Fondamentaux

Pour comprendre le fonctionnement du système, il est essentiel de maîtriser les concepts suivants :

### A. Le Registre Immuable (`Ledger`)

Le cœur du système est un registre d'événements immuable, de type "journal d'audit" ou "blockchain", qui sert de **source unique de vérité**. Chaque action significative (une connexion, une demande de verrou, une mise à jour de rôle) est enregistrée comme un `LogEntry`. Ces entrées sont chaînées cryptographiquement les unes aux autres via un hachage **SHA-256**, rendant l'historique infalsifiable. Toute modification d'un événement passé briserait la chaîne et serait immédiatement détectée.

### B. L'Identité Cryptographique

Chaque pair sur le réseau possède une identité cryptographique unique sous la forme d'une paire de clés **Ed25519**. La clé privée, protégée sur le disque par un mot de passe et une combinaison d'**Argon2** et **ChaCha20-Poly135**, est utilisée pour signer numériquement toutes les actions importantes. La clé publique est partagée et permet aux autres pairs de vérifier ces signatures. Ce mécanisme garantit que chaque action est authentifiée et ne peut être répudiée.

### C. Le Réseau P2P (`libp2p`)

Toutes les communications passent par le framework `libp2p`. Les connexions sont sécurisées de bout en bout (via le protocole `noise`), et la découverte de pairs se fait de manière décentralisée grâce à une table de hachage distribuée (DHT Kademlia).

### D. Le Contrôle d'Accès Basé sur les Rôles (ACL)

Le système implémente un contrôle d'accès basé sur trois rôles :
- **`Reader`** : Peut consulter l'état et télécharger des fichiers.
- **`Contributor`** : Peut demander des verrous et proposer des modifications de fichiers.
- **`Admin`** : Peut modifier les rôles des autres pairs.

L'état des permissions est dérivé directement du registre. Le premier pair à initialiser le réseau devient `Admin` par défaut.

### E. Le Système de Verrouillage Distribué (`Locking`)

Pour éviter les conflits d'édition, un pair doit obtenir un "verrou" (ou "bail") sur un fichier avant de le modifier. Ce verrou est accordé par consensus des autres pairs, qui vérifient dans leur copie du registre qu'aucun autre bail actif n'existe pour ce fichier. Les verrous ont une durée de vie limitée et expirent automatiquement.

### F. Le Transfert de Fichiers par Morceaux (`Chunking`)

Les fichiers volumineux sont divisés en morceaux ("chunks") de 1 Mo. Un **`FileManifest`** (manifeste de fichier) est d'abord échangé, décrivant le fichier, son hachage global et le hachage de chaque morceau. Les chunks sont ensuite transférés individuellement. Le destinataire vérifie le hachage de chaque morceau, garantissant l'intégrité du fichier final et permettant de reprendre un téléchargement interrompu.

---

## 2. Architecture Technique

Le projet est structuré comme un "workspace" Rust, divisé en quatre modules (`crates`) principaux :

- **`crypto`** : Fournit toutes les primitives cryptographiques. Il gère la création, le stockage sécurisé et le chargement des clés, la signature des données et le hachage des fichiers.
- **`ledger_core`** : Implémente la logique du registre immuable, la structure des événements, le chaînage cryptographique et la persistance sur disque.
- **`p2p_core`** : Le cœur de l'application. Il gère la couche réseau avec `libp2p`, définit les protocoles de communication, et implémente toute la logique métier (gestion des verrous, transfert de fichiers, ACL). Il contient à la fois la logique du serveur (`run_server`) et du client (`run_client`).
- **`cli_app`** : Le point d'entrée de l'application. Il fournit une interface en ligne de commande (`CLI`) conviviale pour que l'utilisateur puisse interagir avec le système, en analysant les commandes et en appelant les fonctions appropriées des autres modules.

---

## 3. Guide d'Installation

Pour compiler le projet, vous devez avoir Rust et Cargo d'installés.

```bash
# Clonez le dépôt (exemple)
# git clone <url_du_depot>
# cd secure_p2p

# Compilez le projet
cargo build --release

# L'exécutable se trouvera dans ./target/release/cli_app
```

---

## 4. Manuel d'Utilisation de la CLI

L'exécutable `cli_app` est l'outil principal pour interagir avec le réseau.

### Démarrer un Nœud

Un nœud est un pair qui tourne en continu, écoute les requêtes et participe à la vie du réseau.

- **Démarrer un nœud et attendre des connexions :**
  ```bash
  ./cli_app listen
  ```
  Le nœud affichera son adresse (`Multiaddr`). Gardez-la pour que d'autres puissent se connecter.

- **Démarrer un nœud et se connecter à un pair existant :**
  ```bash
  ./cli_app dial --remote-addr <multiaddr_du_pair_distant>
  ```

### Gérer les Fichiers

- **Demander un verrou sur un fichier :**
  Avant de modifier un fichier, vous devez obtenir un verrou.
  ```bash
  ./cli_app request-lock --file-path "mon_fichier.txt" --peers <addr_peer1>,<addr_peer2>
  ```
  La commande ne réussit que si **tous** les pairs spécifiés accordent le verrou.

- **Notifier une mise à jour de fichier (après modification) :**
  Après avoir modifié un fichier pour lequel vous détenez un verrou, notifiez les autres pairs.
  ```bash
  ./cli_app update-file --file-path "mon_fichier.txt" --peers <addr_peer1>,<addr_peer2>
  ```

- **Télécharger un fichier depuis un pair :**
  ```bash
  ./cli_app transfer-file --file-path "mon_fichier.txt" --peer-addr <addr_du_pair_source>
  ```

### Administration et Inspection

- **Changer le rôle d'un pair (Admin requis) :**
  ```bash
  ./cli_app set-role --peer-id <peer_id_cible> --role Contributor --admin-peer <addr_du_pair_admin>
  ```
  Les rôles possibles sont `Reader`, `Contributor`, `Admin`.

- **Afficher l'historique des événements :**
  Inspectez le contenu du registre local.
  ```bash
  ./cli_app ledger
  # Pour une sortie brute en JSON
  ./cli_app ledger --json
  ```

- **Afficher l'état des permissions :**
  Consultez la liste des rôles actuels, reconstituée à partir du registre.
  ```bash
  ./cli_app show-roles
  ```

---

## 5. Exemple de Scénario d'Utilisation

Voici un flux de travail typique pour deux utilisateurs, **Alice (Admin)** et **Bob (Reader)**.

1.  **Alice démarre le premier nœud :**
    ```bash
    # Alice lance son nœud
    ./cli_app listen
    # Sortie: Listening on /ip4/127.0.0.1/tcp/51234
    ```
    Alice est maintenant `Admin` car elle est la première sur le réseau.

2.  **Bob rejoint le réseau :**
    ```bash
    # Bob se connecte au nœud d'Alice
    ./cli_app dial --remote-addr /ip4/127.0.0.1/tcp/51234
    ```
    Bob est par défaut un `Reader`.

3.  **Alice promeut Bob au rang de `Contributor` :**
    Bob communique son `PeerId` à Alice. Alice exécute alors :
    ```bash
    # Alice (sur sa machine)
    ./cli_app set-role --peer-id <peer_id_de_bob> --role Contributor --admin-peer /ip4/127.0.0.1/tcp/51234
    ```

4.  **Bob veut modifier `projet.txt` :**
    Bob a besoin d'un verrou. Il le demande au nœud d'Alice :
    ```bash
    # Bob (sur sa machine)
    ./cli_app request-lock --file-path "projet.txt" --peers /ip4/127.0.0.1/tcp/51234
    ```

5.  **Bob modifie le fichier et notifie la mise à jour :**
    Une fois le verrou obtenu, Bob modifie `projet.txt` localement. Ensuite, il publie la mise à jour :
    ```bash
    # Bob
    ./cli_app update-file --file-path "projet.txt" --peers /ip4/127.0.0.1/tcp/51234
    ```
    Un événement `FileUpdated` est enregistré dans le registre de tous les pairs connectés.

6.  **Alice télécharge la nouvelle version :**
    ```bash
    # Alice
    ./cli_app transfer-file --file-path "projet.txt" --peer-addr <addr_de_bob>
    ```
Le système garantit que chaque étape a été authentifiée, autorisée et enregistrée de manière immuable.
