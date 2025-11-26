// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    println!("Démarrage de l'application...");
    if let Err(e) = p2p_ui_lib::run() {
        eprintln!("[ERREUR] L'application a échoué au démarrage : {}", e);
        eprintln!("Appuyez sur Entrée pour quitter.");
        let mut stdin = std::io::stdin();
        let _ = stdin.read_line(&mut String::new());
    }
}
