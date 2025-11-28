use tauri::Manager;
use tokio::sync::{mpsc, Mutex};
use p2p_core::run_server;
use crypto_core::{Keypair, keypair_exists, load_keypair, generate_keypair, save_keypair};
use std::sync::Arc;
use ledger_core::Role;
use p2p_core::P2pCommand;

// --- État global géré par Tauri ---
struct AppState {
    command_sender: Arc<Mutex<mpsc::Sender<P2pCommand>>>,
}

// --- Commandes Tauri exposées à l'interface ---

#[tauri::command]
async fn creer_session(app_handle: tauri::AppHandle, chemin_dossier: String, passphrase: Option<String>) -> Result<String, String> {

    let keypair = match manage_keypair_for_ui(passphrase).await {
        Ok(kp) => kp,
        Err(e) => return Err(e),
    };

    let (addr_tx, mut addr_rx) = mpsc::channel(1);
    let (cmd_tx, cmd_rx) = mpsc::channel(32); // Canal pour les commandes

    // Stocker l'émetteur de commandes dans l'état de l'application
    let state = app_handle.state::<AppState>();
    *state.command_sender.lock().await = cmd_tx;

    let app_handle_clone = app_handle.clone();
    tokio::spawn(async move {
        println!("Démarrage du serveur P2P pour le dossier : {}", chemin_dossier);
        if let Err(e) = run_server(keypair, None, Some(addr_tx), Some(app_handle_clone), Some(cmd_rx)).await {
            eprintln!("Le serveur P2P a rencontré une erreur : {}", e);
        }
    });

    match addr_rx.recv().await {
        Some(addr) => Ok(addr),
        None => Err("Le serveur P2P n'a pas pu démarrer ou communiquer son adresse.".into()),
    }
}

#[tauri::command]
async fn rejoindre_session(app_handle: tauri::AppHandle, remote_addr: String, passphrase: Option<String>) -> Result<(), String> {

    let keypair = match manage_keypair_for_ui(passphrase).await {
        Ok(kp) => kp,
        Err(e) => return Err(e),
    };

    let remote_multiaddr = remote_addr.parse().map_err(|e| format!("Adresse distante invalide : {}", e))?;
    let (cmd_tx, cmd_rx) = mpsc::channel(32);

    let state = app_handle.state::<AppState>();
    *state.command_sender.lock().await = cmd_tx;

    let app_handle_clone = app_handle.clone();
    tokio::spawn(async move {
        println!("Connexion au pair distant : {}", remote_addr);
        if let Err(e) = run_server(keypair, Some(remote_multiaddr), None, Some(app_handle_clone), Some(cmd_rx)).await {
            eprintln!("Le serveur P2P a rencontré une erreur : {}", e);
        }
    });

    Ok(())
}


#[tauri::command]
fn check_keypair_exists() -> bool {
    keypair_exists()
}

#[tauri::command]
fn list_files(path: String) -> Result<Vec<String>, String> {
    std::fs::read_dir(path)
        .map_err(|e| e.to_string())?
        .map(|res| res.map(|e| e.file_name().into_string().unwrap()))
        .collect::<Result<Vec<String>, _>>()
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn definir_role(state: tauri::State<'_, AppState>, target_peer_id: String, role: String) -> Result<(), String> {
    let role_enum = match role.as_str() {
        "Lecteur" => Role::Reader,
        "Contributeur" => Role::Contributor,
        "Admin" => Role::Admin,
        _ => return Err("Rôle invalide.".into()),
    };

    let cmd = P2pCommand::SetRole { target_peer_id, role: role_enum };
    state.command_sender.lock().await.send(cmd).await.map_err(|e| e.to_string())?;
    Ok(())
}


// --- Logique privée pour la gestion des clés ---
async fn manage_keypair_for_ui(passphrase: Option<String>) -> Result<Keypair, String> {
    // ... (le code reste le même)
    if keypair_exists() {
        let pass = passphrase.ok_or_else(|| "Mot de passe requis.".to_string())?;
        load_keypair(&pass).map_err(|e| e.to_string())
    } else {
        let pass = passphrase.ok_or_else(|| "Mot de passe requis.".to_string())?;
        let keypair = generate_keypair();
        save_keypair(&keypair, &pass).map_err(|e| e.to_string())?;
        Ok(keypair)
    }
}


// --- Commandes d'administration (stubs à supprimer) ---
#[tauri::command]
async fn voir_historique(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.command_sender.lock().await.send(P2pCommand::ViewHistory).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn voir_roles(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.command_sender.lock().await.send(P2pCommand::ViewRoles).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn update_file(state: tauri::State<'_, AppState>, file_path: String) -> Result<(), String> {
    state.command_sender.lock().await.send(P2pCommand::UpdateFile { file_path }).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn transfer_file(state: tauri::State<'_, AppState>, file_path: String, target_peer_id: String) -> Result<(), String> {
    state.command_sender.lock().await.send(P2pCommand::TransferFile { file_path, target_peer_id }).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn get_my_role(_state: tauri::State<'_, AppState>) -> Result<String, String> {
    // This is a simplified version. A real implementation would query the RoleRegistry.
    // For now, we'll assume the UI creator is always the first admin.
    Ok("Admin".to_string())
}


use std::error::Error;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> Result<(), Box<dyn Error>> {
    let (cmd_tx, _) = mpsc::channel(32); // Créer un canal factice au démarrage

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState { command_sender: Arc::new(Mutex::new(cmd_tx)) })
        .invoke_handler(tauri::generate_handler![
            creer_session,
            rejoindre_session,
            check_keypair_exists,
            definir_role,
            voir_historique,
            voir_roles,
            update_file,
            transfer_file,
            list_files,
            get_my_role
        ])
        .run(tauri::generate_context!())?;

    Ok(())
}
