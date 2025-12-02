# Travaux Restants et Améliorations Techniques (À Finir)

Ce document liste les points techniques identifiés comme nécessitant une attention particulière, une refonte ou une implémentation future pour atteindre l'objectif final de "Zéro Corruption" et "Performance Maximale".

## 1. Performance et Non-Blocage (Blocking I/O)
*   **Problème Actuel :** La fonction `reconstruct_file` (reconstruction de fichier à partir de chunks) utilise des opérations d'entrée/sortie synchrones (`std::fs`). Lorsqu'elle est appelée depuis la boucle d'événements asynchrone (`p2p_core`), cela peut bloquer le thread réseau entier pendant l'écriture de gros fichiers, causant des timeouts ou des pertes de paquets.
*   **Solution Recommandée :** Envelopper tous les appels à `reconstruct_file` dans `tokio::task::spawn_blocking` pour décharger le travail lourd sur un thread dédié sans bloquer le réseau.

## 2. Gestion des Fichiers Vides
*   **Problème Actuel :** Le client de transfert (`run_client`) attend que `received_count` soit égal à `total_chunks`. Si un fichier est vide (0 octet), `total_chunks` est 0, et la boucle de téléchargement ne s'initie jamais correctement ou peut se bloquer indéfiniment selon la logique de contrôle.
*   **Solution Recommandée :** Ajouter une vérification explicite : si `manifest.chunk_hashes.is_empty()`, créer immédiatement le fichier vide et terminer le transfert sans passer par la boucle de chunks.

## 3. Optimisation Réseau (Sliding Window)
*   **Problème Actuel :** La fonction `initiate_file_download` demande *tous* les chunks d'un fichier simultanément. Pour un fichier de 10 Go (10 000 chunks), cela inonde le réseau de 10 000 requêtes instantanées, ce qui peut saturer la bande passante ou la pile de contrôle.
*   **Solution Recommandée :** Implémenter un mécanisme de "fenêtre glissante" (Sliding Window) ou un sémaphore pour limiter le nombre de requêtes de chunks en vol (ex: max 50 chunks simultanés).

## 4. Vérification des Signatures Côté Serveur
*   **Problème Actuel :** Dans `p2p_core/src/lib.rs`, la fonction `handle_chunk_response` vérifie la décompression mais la vérification de la signature cryptographique (`SignedPayload`) est simplifiée ou absente comparé au client.
*   **Solution Recommandée :** Ajouter une vérification stricte de la signature Ed25519 de l'expéditeur pour chaque chunk reçu par le serveur, afin d'empêcher l'injection de données corrompues par un pair malveillant.

## 5. Câblage Complet du Moteur de Synchro (SyncEngine)
*   **Problème Actuel :** `SyncEngine` détecte bien les changements de fichiers locaux, mais l'intégration pour déclencher automatiquement `UpdateFile` et propager les suppressions (`FileDeleted`) n'est pas entièrement finalisée dans la boucle principale.
*   **Solution Recommandée :** Connecter les événements `SyncEvent::FileDeleted` au protocole réseau pour propager les suppressions aux autres pairs.

## 6. Dépendances
*   **Vérification :** Bien que le code compile, il faut s'assurer que `lz4_flex` est déclaré explicitement dans le `Cargo.toml` de `chunk_engine` pour garantir la portabilité des builds futurs.
