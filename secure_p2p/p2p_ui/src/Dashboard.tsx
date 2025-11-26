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

// --- Composant AdminPanel ---
const AdminPanel = () => {
    return (
      <div className="admin-panel">
        <h3>Panneau d'Administration</h3>
        {/* La logique de changement de rôle et les boutons d'information seront ici */}
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
  const [currentUserRole, setCurrentUserRole] = useState("Lecteur"); // Default to reader

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
    const fullPath = await join(sharedFolderPath, fileName);
    invoke('update_file', { filePath: fullPath });
    alert(`Mise à jour pour "${fileName}" envoyée.`);
  };

  const handleTransfer = async (fileName: string) => {
    const targetPeer = prompt('Entrez l\'ID du pair depuis lequel télécharger :');
    if (targetPeer) {
      const fullPath = await join(sharedFolderPath, fileName);
      invoke('transfer_file', { filePath: fullPath, targetPeerId: targetPeer });
      alert(`Demande de transfert pour "${fileName}" envoyée à ${targetPeer}.`);
    }
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
                {files.map(file => (
                    <li key={file}>
                        <span>{file}</span>
                        <div className="file-actions">
                            <button className="button-outline" onClick={() => handleUpdate(file)}>Mettre à jour</button>
                            <button className="button-outline" onClick={() => handleTransfer(file)}>Télécharger</button>
                        </div>
                    </li>
                ))}
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
