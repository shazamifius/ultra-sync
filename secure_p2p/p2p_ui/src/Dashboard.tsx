import React, { useState, useEffect } from 'react';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import InfoModal from './InfoModal';
import { join } from '@tauri-apps/api/path';

// --- Interfaces ---
interface Participant { id: string; name: string; role: string; }
interface PeerPayload { peer_id: string; }
interface LedgerEntryPayload { timestamp: string; peer_id: string; event_info: string; }
interface RoleEntryPayload { peer_id: string; role: string; }

// Updated Interface for Presence
interface PresenceState {
  file_path: string;
  status: string;
  peer_id: string;
}

// --- Composant AdminPanel ---
const AdminPanel = () => {
    return (
      <div className="admin-panel">
        <h3>Panneau d'Administration</h3>
        <div className="admin-section">
          <h4>Consulter les informations</h4>
          <div className="info-buttons">
              <button className="button-outline" onClick={() => invoke('voir_historique')}>Voir l'historique</button>
              <button className="button-outline" onClick={() => invoke('voir_roles')}>Voir les permissions</button>
          </div>
        </div>
      </div>
    );
  };

// --- Composant Dashboard ---
interface DashboardProps {
  onDisconnect: () => void;
  sharingAddress: string;
  sharedFolderPath: string;
}

const Dashboard: React.FC<DashboardProps> = ({ onDisconnect, sharingAddress, sharedFolderPath }) => {
  const [participants, setParticipants] = useState<Participant[]>([]);
  const [files, setFiles] = useState<string[]>([]);
  const [modal, setModal] = useState({ isOpen: false, title: '', data: [] as any[] });
  const [currentUserRole, setCurrentUserRole] = useState("Lecteur");
  const [presences, setPresences] = useState<PresenceState[]>([]); // New state for presences

  const status = "Connecté";
  const [showAdminPanel, setShowAdminPanel] = useState(false);

  useEffect(() => {
    invoke<string>('get_my_role').then(setCurrentUserRole);
    invoke<string[]>('list_files', { path: sharedFolderPath }).then(setFiles);

    const unlisteners = [
      listen<PeerPayload>('peer-connected', (event) => {
        setParticipants((prev) => [...prev, { id: event.payload.peer_id, name: `${event.payload.peer_id.substring(0, 12)}...`, role: 'Lecteur' }]);
      }),
      listen<PeerPayload>('peer-disconnected', (event) => {
        setParticipants((prev) => prev.filter((p) => p.id !== event.payload.peer_id));
      }),
      listen<LedgerEntryPayload[]>('history-updated', (event) => {
        setModal({ isOpen: true, title: 'Historique du Registre', data: event.payload });
      }),
      listen<RoleEntryPayload[]>('roles-updated', (event) => {
        setModal({ isOpen: true, title: 'Registre des Rôles', data: event.payload });
      }),
      // Listen for Presence Updates
      listen<PresenceState>('presence-updated', (event) => {
         setPresences(prev => {
             // Replace existing entry for this peer+file or add new
             const filtered = prev.filter(p => !(p.peer_id === event.payload.peer_id && p.file_path === event.payload.file_path));
             return [...filtered, event.payload];
         });
      }),
    ];

    return () => {
      unlisteners.forEach(unlisten => unlisten.then(f => f()));
    };
  }, [sharedFolderPath]);

  const handleCopyAddress = () => {
    navigator.clipboard.writeText(sharingAddress);
    alert('Adresse copiée dans le presse-papiers !');
  };

  const handleUpdate = async (fileName: string) => {
    // Notify that I am editing
    const fullPath = await join(sharedFolderPath, fileName);
    invoke('set_presence', { filePath: fullPath, status: "Editing" });

    // In a real app, this would open the file, etc.
    // For now, we simulate an "update" trigger
    invoke('update_file', { filePath: fullPath });
    alert(`Mise à jour pour "${fileName}" envoyée.`);

    // Reset presence after a delay
    setTimeout(() => {
        invoke('set_presence', { filePath: fullPath, status: "Idle" });
    }, 5000);
  };

  const getPresenceForFile = (fileName: string) => {
      // Logic to find active presences for this file (ignoring full path for simple match for now)
      return presences.filter(p => p.file_path.includes(fileName) && p.status === "Editing");
  };

  return (
    <>
      <InfoModal isOpen={modal.isOpen} title={modal.title} data={modal.data} onClose={() => setModal({ ...modal, isOpen: false })} />
      <div className="dashboard-container">
        <header className="dashboard-header">
            <h1>Session de Partage Active</h1>
            <p>Dossier partagé : <strong>{sharedFolderPath}</strong></p>
        </header>

        <div className="dashboard-content">
          <div className="dashboard-card status-card">
            <h2>Statut de la Connexion</h2>
            <p className="status-indicator status-ok">{status}</p>
            <div className="sharing-address">
                <span>Votre Adresse de Partage :</span>
                <div className="address-box">
                <input type="text" readOnly value={sharingAddress} />
                <button onClick={handleCopyAddress}>Copier</button>
                </div>
            </div>
          </div>
          <div className="dashboard-card participants-card">
            <h2>Participants</h2>
            {participants.length === 0 ? <p>En attente de participants...</p> : <ul>{participants.map(p => <li key={p.id}><span className="participant-name">{p.name}</span><span className={`participant-role role-${p.role.toLowerCase()}`}>{p.role}</span></li>)}</ul>}
          </div>
        </div>

        <div className="dashboard-card file-list-card">
            <h2>Fichiers Partagés</h2>
            <ul>
                {files.map(file => {
                    const activeEditors = getPresenceForFile(file);
                    return (
                    <li key={file}>
                        <div className="file-info">
                            <span>{file}</span>
                            {activeEditors.length > 0 && (
                                <span className="presence-badge">
                                    ✏️ {activeEditors.length} éditeur(s)
                                </span>
                            )}
                        </div>
                        <div className="file-actions">
                            <button className="button-outline" onClick={() => handleUpdate(file)}>Editer / Mettre à jour</button>
                        </div>
                    </li>
                )})}
            </ul>
        </div>

        {currentUserRole === 'Admin' && (
            <div className="admin-toggle">
                <button className="button-outline" onClick={() => setShowAdminPanel(!showAdminPanel)}>
                    {showAdminPanel ? "Cacher l'administration" : "Afficher l'administration"}
                </button>
            </div>
        )}
        {showAdminPanel && <AdminPanel />}

        <footer className="dashboard-footer">
            <button onClick={onDisconnect} className="button-danger">
                Quitter la session
            </button>
        </footer>
      </div>
    </>
  );
};

export default Dashboard;
