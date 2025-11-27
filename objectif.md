# Objectif du Projet

Ce document sert de référence officielle du projet. Il décrit **l’objectif final**, **l’architecture globale**, **les systèmes internes**, **les garanties de sécurité**, **les comportements attendus**, **les contraintes**, et **le fonctionnement complet** du futur logiciel de synchronisation P2P.

---

# 1. Vision Générale du Projet

Créer un système de synchronisation de fichiers **100 % pair-à-pair**, **ultra-rapide**, **ultra-fiable**, et **inviolable**, destiné à un usage grand public.

Ce système doit :

* Synchroniser automatiquement des dossiers entre plusieurs machines.
* Fonctionner sans serveur, sans cloud, sans nœud central, sans dépendance externe.
* Assurer une cohérence parfaite des données même en cas de crash, coupure de courant ou fork du réseau.
* Être résistant aux attaques, falsifications, corruptions et pertes de données.
* Offrir un système anti‑écrasement pour les fichiers binaires utilisés dans les workflows créatifs (ex: Blender).
* Rester extrêmement simple à utiliser pour l'utilisateur final.

---

# 2. Principes Fondamentaux

### 2.1. P2P pur

* Communication directe entre pairs.
* Découverte locale via mDNS.
* Invitation cryptographique pour les pairs distants.
* Aucun serveur de bootstrap obligatoire.

### 2.2. Synchronisation incrémentale

* Le système ne transfère jamais un fichier entier si ce n’est pas nécessaire.
* Les fichiers sont découpés en blocs (chunks), hashés, et seulement les blocs modifiés sont envoyés.

### 2.3. Hash immuable

Chaque bloc est vérifié avec un hash cryptographique :

* Garantit l’intégrité.
* Empêche modification à distance.
* Permet détection de divergence.

### 2.4. Ledger immuable local

Toutes les modifications sont inscrites dans un petit journal local afin de :

* Détecter les crashs.
* Rejouer ou annuler des opérations.
* Restaurer l’état stable.

### 2.5. Système anti‑écrasement

* Aucun utilisateur ne peut écraser un fichier utilisé par un autre.
* Verrouillage automatique avec un `.lock` distribué P2P.
* Création de copies de conflit si deux utilisateurs modifient la même version en parallèle.

### 2.6. Sécurité et cryptographie

* Ed25519 pour les signatures.
* ChaCha20‑Poly1305 pour le transport encrypté.
* OS keyring pour stocker la clé privée.

---

# 3. Fonctionnement Global

## 3.1. Surveillance des fichiers

Un watcher surveille :

* modifications
* suppressions
* nouveaux fichiers

Quand un fichier change :

1. Le moteur découpe en chunks.
2. Hash chaque chunk.
3. Compare avec l'état local.
4. Produit un “delta”.
5. Publie l’évènement aux peers.

## 3.2. Diffusion (Gossip)

Chaque nœud diffuse :

* sa version des fichiers
* les chunks manquants ou modifiés
* son état de verrouillage
* l’état d’un fichier en cours d’usage

## 3.3. Réception des mises à jour

Le pair :

1. Vérifie la signature.
2. Télécharge les chunks manquants.
3. Reconstitue le fichier.
4. Compare les hashes finaux.
5. Écrit le fichier via écriture atomique.

---

# 4. Architecture Technique

## 4.1. Modules Principaux

### **1. `p2p_core`**

* Gestion du réseau libp2p.
* Noise encryption.
* Peer discovery.
* PubSub.
* Sessions de transfert.

### **2. `ledger_core`**

* Journal local immuable.
* Entrées ordonnées.
* Hash chain.

### **3. `chunk_engine`**

* Découpage des fichiers.
* Hashing BLAKE3.
* Compression LZ4.
* Gestion du cache.

### **4. `sync_engine`**

* Coordination de la synchronisation.
* Calcul des deltas.
* Gestion des opérations locales.

### **5. `conflict_solver`**

* Détection de conflits.
* Création de versions alternatives.

### **6. `file_lock`**

* Création/suppression du `.lock`.
* Diffusion P2P de l’état.
* Empêche écrasement.

### **7. `crash_recovery`**

* Journalisation de l’activité.
* Restauration automatique.
* Résolution de divergence par hash.

### **8. UI** (plus tard)

* Interface simple.
* Gestion des dossiers synchronisés.

---

# 5. Systèmes Internes Détaillés

## 5.1. Chunking

* Taille fixe (accélération).
* Option CDC (Content Defined Chunking) pour gros fichiers.

### Métadonnées stockées :

```
chunk_id
hash
compressed_size
original_size
file_version
```

---

## 5.2. Protocole de transfert

```
Peer A → annonce version
Peer B → compare
Peer B → demande chunks manquants
Peer A → envoie chunks
Peer B → reconstruit
Peer B → vérifie hash
```

---

## 5.3. Verrouillage

* Lors d’un "save" : création `.filename.lock`.
* Diffusion P2P.
* Les autres pairs passent en lecture seule.
* Suppression à la fermeture propre.
* Crash → restauration via journal.

---

## 5.4. Crash Recovery

* Entrée dans le journal toutes les X secondes.
* Si dernière entrée incohérente → crash.
* Vérification hash final.
* Re-téléchargement chunks invalides.

---

# 6. Scénarios Complet

## 6.1. Une machine modifie un fichier

1. Watcher détecte modification.
2. Chunking.
3. Hash et delta.
4. Diffusion.
5. Autres pairs appliquent.

## 6.2. Deux machines modifient en même temps

* Système détecte deux versions.
* Première arrivée sur le réseau = version officielle.
* L’autre devient `filename (conflict user).ext`.

## 6.3. Crash pendant sauvegarde

* État incohérent détecté.
* Restauration dernière version stable.
* Synchronisation automatique.

---

# 7. Objectif Final Fonctionnel

Le logiciel final doit :

* Synchroniser un dossier complet en P2P.
* Prévenir toute corruption de fichier.
* Empêcher l’écrasement par des utilisateurs concurrents.
* Gérer les conflits sans perte.
* Restaurer en cas de crash.
* Résister aux attaques (MITM, replays, tampering, impersonation).
* Offrir une vitesse maximum (réseau saturé).
* Être utilisable même pour les gros fichiers 3D.

---

# 8. Contraintes Strictes

* Aucun serveur externe obligatoire.
* Sécurité maximale.
* Code maintenable et modulaire.
* Performances optimales.
* Zéro corruption acceptée.
* Système doit tourner silencieusement en arrière‑plan.

---

# 9. Roadmap

### Phase 1 – Prototype minimal

* P2P libp2p
* Watcher local
* Chunk engine simple
* Transfert bloc + hash

### Phase 2 – Systèmes avancés

* Ledger
* Crash Recovery
* Lock distribué
* Conflits

### Phase 3 – Optimisations

* compression
* pipeline multi‑thread
* UI
* CDC

---

# 10. Définition du succès

Le projet est réussi si :

* Les fichiers restent toujours intacts.
* La synchronisation est plus rapide que Resilio Sync.
* Le système fonctionne même après un crash violent.
* Aucun piratage ne peut altérer les fichiers.
* Les utilisateurs ne perdent jamais un travail.

---


## 1. Philosophie : "Jamais Bloqué, Jamais Perdu"

L'utilisateur doit pouvoir travailler **immédiatement**, tout le temps, avec ou sans internet. Le logiciel ne doit jamais lui dire "Non, tu ne peux pas toucher à ce fichier".

### Le fonctionnement par défaut :
1.  **Tout le monde peut tout modifier** à tout moment.
2.  **Zéro attente :** Pas de demande de permission au réseau.
3.  **Filet de sécurité invisible :** Le système gère les collisions en arrière-plan sans embêter l'utilisateur.

---

## 2. La Solution Anti-Conflit (Sans Lock)

Au lieu d'empêcher les gens de travailler (Lock), on utilise une **Détection de Présence** et des **Copies de Sauvegarde**.

### 2.1. Signalisation "Douce" (UI seulement)
Au lieu d'un cadenas bloquant, on affiche une simple **information visuelle**.
* *Scénario :* Alice ouvre `Projet.psd`.
* *Chez Bob :* Une petite bulle apparaît : *"Alice est dessus en ce moment"*.
* *Action :* Bob **PEUT** quand même ouvrir et modifier le fichier s'il le veut (car c'est permissif). Il est juste prévenu.

### 2.2. Gestion des Collisions (Le Filet de Sécurité)
Si Alice et Bob modifient le même fichier en même temps (ou si Alice a crashé et que Bob reprend la main) :
1.  Le système compare les fichiers.
2.  Si les fichiers sont différents, **IL NE CHOISIT PAS**. Il garde les deux.
3.  Le fichier d'Alice reste `Projet.psd`.
4.  Le fichier de Bob est sauvegardé instantanément à côté sous le nom `Projet (Conflit Bob - 14h30).psd`.

**Avantage :** Aucun risque d'écraser le travail de l'autre, et aucun risque d'être bloqué par un "fantôme" qui a perdu sa connexion.

---

## 3. Résistance aux Crashs (Le "Journal de Réparation")

C'est ici que le journal est utile. Il ne sert pas à bloquer, mais à **réparer**.

* *Le problème :* L'ordi coupe pendant une écriture de fichier (coupure de courant).
* *La solution :* Au redémarrage, le logiciel lit son petit journal local : *"Tiens, je n'ai pas fini d'écrire le fichier X"*.
* *L'action :* Il invalide le fichier corrompu et retélécharge les bouts manquants chez les autres pairs. C'est automatique et invisible.

---

## 4. Les Options Utilisateur (Pour les Power Users)

Comme demandé, on ajoute des réglages pour ceux qui veulent contrôler le comportement :

* **Mode "Zen" (Par défaut) :** Permissif. Si conflit -> création de copie. Pas de pop-up intrusif.
* **Mode "Avertissement" :** Si j'essaie d'ouvrir un fichier qu'un autre utilise, une pop-up me demande : *"Alice est dessus, voulez-vous vraiment modifier ?"* (Oui/Non).
* **Mode "Strict" (Désactivé par défaut) :** Pour les équipes rigides qui *veulent* un verrouillage bloquant (type entreprise).

---

## 5. Architecture Technique Mise à Jour

Pour coller à cette vision permissive :

1.  **`Presence_Monitor` (Nouveau module) :** Remplace le `Lock_Manager`. Il diffuse juste des infos "Je suis là", "Je bosse sur ça". Si le message ne vient plus (coupure wifi), l'info disparaît d'elle-même après 30 secondes. Pas de blocage éternel.
2.  **`Conflict_Solver` :** Logique simple -> Si deux hashes différents pour le même fichier au même moment = Renommage automatique.
3.  **`Chunk_Engine` :** Toujours là pour la vitesse (découpage + compression).
4.  **`Crypto_Core` :** Toujours là pour la sécurité (Zero Knowledge).
