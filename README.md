# Guide de Référence du Projet (Fin de l'Étape 3)

Ce document sert à la fois d'audit de l'état actuel du système et de documentation de référence pour les développeurs et les parties prenantes.

## 1. 🗺️ État Global du Projet et Prochaines Étapes

*   **Bilan :**
    Le projet a successfully complété trois étapes fondamentales :
    1.  **Étape 1 (Canal P2P) :** Mise en place d'un canal de communication direct et sécurisé entre les pairs en utilisant `libp2p`, avec un chiffrement de bout en bout et une identification cryptographique des participants.
    2.  **Étape 2 (Ledger Immuable) :** Création d'un journal d'événements (ledger) distribué et infalsifiable, où chaque nouvelle entrée est chaînée cryptographiquement à la précédente, garantissant l'intégrité de l'historique des actions.
    3.  **Étape 3 (Verrouillage/Transfert) :** Implémentation de la logique métier principale, permettant à un pair de demander un "verrou" (bail) sur un fichier avant de le modifier, et de transférer des fichiers volumineux de manière sécurisée et vérifiable.

*   **Capacités Actuelles :**
    Aujourd'hui, le système peut **établir une connexion sécurisée entre pairs, et transférer un fichier sous un régime de verrouillage distribué** pour éviter les conflits d'écriture.

*   **Prochaine Cible (Étape 4) :**
    La prochaine fonctionnalité critique à implémenter est la **gestion des permissions et des rôles (ACL - Access Control List)**. Cela permettra de définir quel pair a le droit d'effectuer quelles actions (par exemple, demander un verrou, modifier un fichier), ajoutant une couche de contrôle d'accès au-dessus du mécanisme de verrouillage existant.

---

## 2. 📦 Guide Détaillé des Composants (Crates)

### A. Crate `crypto` (Sécurité Pure)

*   **Rôle :**
    Ce module est la base de la sécurité de l'application. Il est responsable de la gestion des identités cryptographiques (clés), de la signature des données pour assurer leur authenticité et leur intégrité, du hachage de fichiers volumineux de manière performante, et du chiffrement des clés privées stockées sur le disque. Il **ne gère pas** la logique de communication réseau.

*   **Implémentation :**
    *   **Signature :** L'algorithme **Ed25519** est utilisé pour la signature des messages. Il offre une haute performance et des garanties de sécurité robustes.
    *   **Chiffrement :** Les clés privées sont stockées sur le disque de manière chiffrée. Le processus utilise une combinaison de :
        *   **Argon2 :** Un algorithme de dérivation de clé (KDF) robuste qui transforme le mot de passe de l'utilisateur en une clé de chiffrement, tout en étant résistant aux attaques par force brute.
        *   **ChaCha20-Poly1305 :** Un algorithme de chiffrement authentifié (AEAD) qui chiffre la clé privée en utilisant la clé dérivée par Argon2.

### B. Crate `ledger_core` (Intégrité des Données)

*   **Rôle :**
    Ce module implémente la structure de données de type blockchain/ledger qui garantit un
    historique immuable et vérifiable de tous les événements importants du système (connexions,
    demandes de verrou, etc.). Chaque "bloc" est une entrée de log (`LogEntry`) contenant l'événement,
    l'identité du pair, un horodatage, et une preuve cryptographique.

*   **Implémentation :**
    *   **Chaînage :** L'intégrité de la chaîne est assurée par un hachage cryptographique. Chaque
      entrée contient le hash de l'entrée précédente (`prev_hash`), et son propre hash est calculé
      sur l'ensemble de ses données. L'algorithme de hash utilisé est le **SHA-256**.
    *   **Persistance :** Les entrées du ledger sont sérialisées dans un format binaire compact et
      performant, le **Bincode**, puis écrites séquentiellement dans un fichier sur le disque
      (`p2p_ledger.dat`). Ce choix est plus efficace que des formats texte comme JSON pour des
      données structurées.

### C. Crate `p2p_core` (Logique Métier et Réseau)

*   **Rôle :**
    C'est le cœur de l'application, qui orchestre la communication réseau et implémente la logique
    métier de verrouillage et de transfert de fichiers. Il combine les primitives de `crypto` et
    `ledger_core` pour exécuter les actions des utilisateurs.

*   **Implémentation :**
    *   **Réseau :**
        *   La bibliothèque **`libp2p`** est utilisée pour gérer tous les aspects de la communication
          peer-to-peer (découverte, transport sécurisé, multiplexage).
        *   Un protocole de message unifié basé sur `Request/Response` a été créé. Toutes les
          communications métier passent par des messages `AppRequest` et `AppResponse`, qui
          encapsulent les différentes actions possibles (demande de verrou, transfert de chunk, etc.).
    *   **Transfert :**
        *   **Chunking :** Pour gérer les fichiers volumineux sans surcharger la mémoire ou le
          réseau, les fichiers sont divisés en "chunks" (morceaux) de **1 Mo**. Un `FileManifest`
          est d'abord envoyé, décrivant le fichier complet et les hashes de chaque chunk. Le
          destinataire télécharge ensuite les chunks un par un et les ré-assemble.
        *   **Sécurité :** Chaque chunk est accompagné d'une **signature numérique** du pair
          expéditeur, permettant de vérifier son authenticité et son intégrité à la réception.
    *   **Verrouillage :**
        *   Le système utilise une logique de **bail (Leasing)**. Un pair demandant un verrou
          spécifie une durée. Si le verrou est accordé (après vérification qu'aucun autre bail n'est
          actif pour ce fichier dans le ledger), une entrée `LockGranted` est ajoutée au ledger avec
          une date d'expiration.
        *   Ce mécanisme prévient les conflits en s'assurant qu'un seul pair peut obtenir un "droit
          d'écriture" sur un fichier à un moment donné, et ce droit est validé de manière
          décentralisée par l'état du ledger partagé.

---

## 3. 🛠️ Guide d'Utilisation des Commandes CLI

### `secure_p2p listen / dial`

*   **Action :** Ces commandes démarrent un nœud P2P en mode serveur persistant.
*   **Flux d'événements :**
    *   `listen` : Le nœud démarre et écoute les connexions entrantes sur une adresse réseau non
      spécifiée (généralement `0.0.0.0` sur un port aléatoire). Il affiche son adresse pour que
      d'autres puissent s'y connecter.
    *   `dial <remote_addr>` : Le nœud démarre et tente immédiatement d'établir une connexion avec
      l'adresse du pair distant fournie.
    *   Une fois connecté, le nœud entre dans une boucle d'événements, répondant aux requêtes
      (demandes de verrou, de chunks, etc.) et envoyant périodiquement des "heartbeats" aux autres
      pairs pour maintenir la connexion et partager l'état.

### `secure_p2p show-ledger`

*   **Action :** Affiche le contenu complet du ledger local (`p2p_ledger.dat`) de manière lisible.
*   **Flux d'événements :**
    1.  Le programme charge le fichier du ledger depuis le disque.
    2.  Il effectue une **vérification d'intégrité** pour s'assurer que la chaîne de hashes n'a pas
      été corrompue.
    3.  Il parcourt chaque `LogEntry` et l'affiche dans un format humainement lisible. L'option
      `--json` permet d'obtenir une sortie brute et structurée, utile pour le débogage.

### `secure_p2p request-lock <filepath>`

*   **Action :** Exécute une commande client pour demander un verrou sur un fichier auprès d'un ou
  plusieurs pairs.
*   **Flux d'événements :**
    1.  Le client se connecte aux pairs spécifiés via leurs adresses.
    2.  Il envoie une requête `LockRequest` signée numériquement à chaque pair.
    3.  Chaque pair récepteur vérifie sa propre copie du ledger pour voir si un **bail actif**
      existe déjà pour ce fichier.
    4.  Si aucun bail n'est actif, le pair distant accorde le verrou et envoie une réponse
      `LockResponse(Granted)`. Il ajoute également un événement `LockGranted` à son ledger local.
    5.  Le client doit recevoir une réponse positive de **tous** les pairs pour considérer la
      commande comme réussie.

### `secure_p2p transfer-file <filepath> <peer_id>`

*   **Action :** Exécute une commande client pour télécharger un fichier depuis un pair distant.
*   **Flux d'événements :**
    1.  Le client se connecte au pair distant.
    2.  Il envoie une requête `ManifestRequest` pour le fichier demandé.
    3.  Le pair distant génère un `FileManifest` (contenant la taille totale, le hash total et les
      hashes de chaque chunk) et le renvoie.
    4.  Le client demande ensuite chaque chunk individuellement en utilisant son index
      (`ChunkRequest`).
    5.  Pour chaque requête, le pair distant lit le chunk correspondant, le signe, et l'envoie dans
      une réponse `ChunkResponse`.
    6.  Le client **vérifie la signature et le hash** de chaque chunk reçu avant de l'écrire sur le
      disque.
    7.  Une fois tous les chunks téléchargés et vérifiés, le fichier est ré-assemblé et le
      transfert est considéré comme réussi.
