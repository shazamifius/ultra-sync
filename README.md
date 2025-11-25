# Secure P2P - Synchronisation de Fichiers Sécurisée

**Secure P2P** est une application de synchronisation de fichiers en peer-to-peer conçue pour offrir un environnement de partage sécurisé, transparent et contrôlé. Elle permet à plusieurs utilisateurs de collaborer sur un ensemble de fichiers tout en garantissant l'intégrité et la traçabilité de chaque action grâce à un système de registre d'événements (ledger) immuable et à un contrôle d'accès basé sur les rôles.

## Objectif du Projet

L'objectif principal de ce projet est de fournir une solution de synchronisation de fichiers qui répond aux exigences suivantes :

- **Sécurité Robuste**: Toutes les communications sont chiffrées de bout en bout, et chaque action est authentifiée par des signatures cryptographiques.
- **Intégrité des Données**: Un registre d'événements (ledger) immuable, basé sur une chaîne de hachage, garantit que l'historique des actions ne peut être altéré.
- **Contrôle d'Accès Granulaire**: Un système de rôles (Lecteur, Contributeur, Admin) permet de définir précisément les permissions de chaque utilisateur.
- **Flexibilité d'Utilisation**: L'application est accessible via une interface en ligne de commande (CLI) pour les utilisateurs avancés et une interface graphique (GUI) pour une utilisation plus intuitive.

## Architecture du Projet

Le projet est structuré en plusieurs modules (`crates`) Rust, chacun ayant un rôle bien défini :

- **`crypto`**: Ce module gère toutes les opérations cryptographiques. Il est responsable de la génération et de la gestion des paires de clés (Ed25519), du chiffrement des clés privées sur le disque (avec Argon2 et ChaCha20-Poly1305), de la signature des données et du hachage des fichiers (SHA-256).

- **`ledger_core`**: Il s'agit du cœur du système de traçabilité. Ce module implémente un registre d'événements immuable où chaque action (connexion, demande de verrou, mise à jour de fichier, etc.) est enregistrée sous forme d'entrée chaînée par hachage.

- **`p2p_core`**: Ce module gère toute la logique réseau peer-to-peer en utilisant le framework `libp2p`. Il est responsable de la découverte des pairs, de l'établissement des connexions, de la gestion des flux de communication et de la définition des protocoles d'échange de messages.

- **`cli_app`**: Il s'agit de l'interface en ligne de commande (CLI) de l'application. Elle permet aux utilisateurs d'interagir avec le système via des commandes textuelles pour lancer un pair, se connecter à un réseau, gérer les fichiers et administrer les rôles.

- **`p2p_ui`**: C'est l'interface graphique utilisateur (GUI) de l'application, développée avec le framework `Tauri` et une interface en `React` (TypeScript). Elle offre une expérience utilisateur plus visuelle et intuitive pour les fonctionnalités de l'application.

## Concepts Fondamentaux

### Sécurité

La sécurité est au cœur de l'application. Chaque pair possède une identité cryptographique unique (une paire de clés Ed25519). Les clés privées sont chiffrées sur le disque avec un mot de passe et ne sont jamais transmises sur le réseau. Toutes les actions importantes sont encapsulées dans une charge utile signée (`SignedPayload`), ce qui permet de vérifier l'authenticité de chaque message.

### Ledger et Intégrité des Données

Le `ledger` est un journal d'événements qui enregistre chaque action effectuée sur le réseau. Chaque entrée contient un horodatage, l'ID du pair, le type d'événement et le hachage de l'entrée précédente. Cette structure de chaîne de hachage garantit qu'une fois qu'une entrée est écrite, elle ne peut plus être modifiée sans invalider toute la chaîne, assurant ainsi une traçabilité et une intégrité totales.

### Synchronisation de Fichiers

Pour transférer des fichiers volumineux de manière efficace, l'application utilise un système de manifeste de fichier. Un manifeste contient des métadonnées sur le fichier, y compris sa taille, le hachage de chaque morceau (chunk) de 1 Mo et le hachage total du fichier. Lorsqu'un pair souhaite télécharger un fichier, il demande d'abord le manifeste, puis télécharge chaque morceau individuellement, en vérifiant le hachage de chacun.

### Contrôle d'Accès (RBAC)

Le système de contrôle d'accès basé sur les rôles (RBAC) définit trois niveaux de permissions :
- **`Reader` (Lecteur)**: Ne peut que recevoir les mises à jour des fichiers.
- **`Contributor` (Contributeur)**: Peut demander des verrous sur les fichiers et les modifier.
- **`Admin` (Administrateur)**: A tous les droits d'un contributeur et peut en plus assigner des rôles aux autres pairs.

## Guide d'Utilisation

### Prérequis

-   **Rust et Cargo**: Nécessaires pour compiler le cœur de l'application. [Instructions d'installation](https://www.rust-lang.org/tools/install).
-   **Node.js et npm**: Nécessaires uniquement si vous souhaitez compiler vous-même l'interface graphique. [Instructions d'installation](https://nodejs.org/).
-   **Dépendances Tauri**: Si vous compilez l'interface graphique, suivez le [guide officiel de Tauri](https://tauri.app/v1/guides/getting-started/prerequisites) pour installer les dépendances spécifiques à votre système d'exploitation (outils de build, webview, etc.).

### Interface en Ligne de Commande (`cli_app`)

#### Compilation
```bash
cd secure_p2p/
cargo build --release -p cli_app
```
L'exécutable se trouvera dans `target/release/cli_app`.

#### Scénario d'Exemple : Alice et Bob

1.  **Alice démarre une session**
    Alice veut partager un dossier. Elle lance la commande `listen` pour démarrer un pair et attendre des connexions. La première fois, elle devra créer un mot de passe pour son identité.
    ```bash
    # Terminal d'Alice
    ./target/release/cli_app listen
    # Le programme affichera l'adresse d'écoute, par exemple :
    # Listening on "/ip4/127.0.0.1/tcp/54321"
    ```
    Alice communique cette adresse à Bob.

2.  **Bob rejoint la session**
    Bob utilise l'adresse d'Alice pour se connecter au réseau.
    ```bash
    # Terminal de Bob
    ./target/release/cli_app dial --remote-addr /ip4/127.0.0.1/tcp/54321
    ```
    Bob est maintenant connecté. Par défaut, il a le rôle de `Reader`.

3.  **Alice promeut Bob**
    Alice, en tant qu'administratrice de la session, peut changer le rôle de Bob. Elle a besoin de l'ID de pair de Bob (qu'elle peut trouver dans les logs ou en utilisant la commande `show-roles`).
    ```bash
    # Terminal d'Alice
    ./target/release/cli_app set-role --peer-id <ID_DE_BOB> --role Contributor --admin-peer /ip4/127.0.0.1/tcp/54321
    ```

4.  **Bob modifie un fichier**
    Maintenant que Bob est `Contributor`, il peut demander un verrou sur un fichier pour le modifier. Il demande un verrou sur `document.txt` à tous les pairs du réseau.
    ```bash
    # Terminal de Bob
    ./target/release/cli_app request-lock --file-path document.txt --peers /ip4/127.0.0.1/tcp/54321
    ```
    Une fois le verrou accordé, Bob peut modifier le fichier localement. Ensuite, il notifie les autres de la mise à jour.
    ```bash
    # Terminal de Bob
    ./target/release/cli_app update-file --file-path document.txt --peers /ip4/127.0.0.1/tcp/54321
    ```

### Interface Graphique (`p2p_ui`)

L'interface graphique est la méthode recommandée pour la plupart des utilisateurs. Elle est autonome et gère le processus de synchronisation en arrière-plan.

#### Compilation (pour les développeurs)

Si vous souhaitez compiler l'application vous-même, suivez ces étapes :

1.  **Naviguez vers le dossier de l'interface :**
    ```bash
    cd secure_p2p/p2p_ui/
    ```

2.  **Installez les dépendances JavaScript :**
    ```bash
    npm install
    ```

3.  **Compilez l'application :**
    Cette commande va créer un exécutable natif pour votre système d'exploitation.
    ```bash
    npm run tauri build
    ```
    L'exécutable final se trouvera dans le dossier `secure_p2p/target/release/`, sous le nom `p2p_ui.exe` (Windows), `p2p_ui` (Linux) ou `p2p_ui.app` (macOS).

#### Utilisation

1.  **Lancement de l'application**
    -   Double-cliquez simplement sur l'exécutable `p2p_ui` que vous avez compilé (ou téléchargé).
    -   **Important**: Il n'est PAS nécessaire de lancer un autre programme. L'interface graphique s'occupe de démarrer le moteur de synchronisation en arrière-plan.

2.  **Premier démarrage**
    -   Si c'est votre première utilisation, l'application vous demandera de créer un mot de passe. Ce mot de passe protège votre clé d'identité unique sur le réseau. **Ne le perdez pas !**

3.  **Démarrer ou rejoindre une session**
    -   **Pour créer une nouvelle session de partage** :
        1.  Cliquez sur le bouton "Choisir un dossier".
        2.  Sélectionnez le dossier que vous souhaitez synchroniser.
        3.  Cliquez sur "Démarrer la session".
        4.  Une adresse unique sera affichée. Copiez-la et partagez-la avec les personnes que vous souhaitez inviter.
    -   **Pour rejoindre une session existante** :
        1.  Collez l'adresse que l'on vous a fournie dans le champ "Adresse du pair distant".
        2.  Cliquez sur "Choisir un emplacement" pour décider où les fichiers synchronisés seront sauvegardés sur votre ordinateur.
        3.  Cliquez sur "Rejoindre".

Une fois connecté, le tableau de bord affiche l'état de la synchronisation, la liste des participants et les options de gestion disponibles.
