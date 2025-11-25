import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-dialog';
import './App.css';
import Dashboard from './Dashboard';
import PasswordModal from './PasswordModal';

type SessionMode = 'create' | 'join';

function App() {
  const [isConnected, setIsConnected] = useState(false);
  const [sessionInfo, setSessionInfo] = useState({ address: '', folderPath: '' });
  const [remoteAddr, setRemoteAddr] = useState('');
  const [localPath, setLocalPath] = useState('');
  const [sharedFolderPath, setSharedFolderPath] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [sessionMode, setSessionMode] = useState<SessionMode>('create');
  const [keypairExists, setKeypairExists] = useState(false);

  useEffect(() => {
    invoke('check_keypair_exists').then((exists) => setKeypairExists(exists as boolean));
  }, []);

  const handleSessionAttempt = (mode: SessionMode) => {
    if (mode === 'create' && !sharedFolderPath) {
      alert('Veuillez sélectionner un dossier à partager.');
      return;
    }
    if (mode === 'join' && (!remoteAddr || !localPath)) {
      alert('Veuillez fournir l\'adresse du pair et choisir un dossier local.');
      return;
    }
    setSessionMode(mode);
    setIsModalOpen(true);
  };

  const handlePasswordSubmit = async (password: string) => {
    try {
      if (sessionMode === 'create') {
        const address = await invoke('creer_session', {
          cheminDossier: sharedFolderPath,
          passphrase: password
        }) as string;
        setSessionInfo({ address, folderPath: sharedFolderPath });
      } else { // mode === 'join'
        await invoke('rejoindre_session', {
          remoteAddr: remoteAddr,
          passphrase: password
        });
        setSessionInfo({ address: 'N/A (connecté)', folderPath: localPath });
      }

      setIsModalOpen(false);
      setIsConnected(true);
    } catch (error) {
      console.error(`Erreur lors de la tentative de ${sessionMode} session:`, error);
      alert(`Une erreur est survenue : ${error}`);
    }
  };

  const handleDisconnect = () => {
      setIsConnected(false);
      setSessionInfo({ address: '', folderPath: '' });
  };

  const selectFolder = async (setter: (path: string) => void) => {
    try {
      const result = await open({ directory: true, multiple: false });
      if (typeof result === 'string') {
        setter(result);
      }
    } catch (e) {
      console.error("Erreur lors de la sélection du dossier:", e);
    }
  };

  if (isConnected) {
    return <Dashboard
             onDisconnect={handleDisconnect}
             sharingAddress={sessionInfo.address}
             sharedFolderPath={sessionInfo.folderPath}
           />;
  }

  return (
    <>
      <PasswordModal
        isOpen={isModalOpen}
        isNewKeypair={!keypairExists}
        onSubmit={handlePasswordSubmit}
        onClose={() => setIsModalOpen(false)}
      />
      <div className="container">
        <header className="header">
          <h1>P2P File Sync</h1>
          <p>Synchronisation de dossiers, simple et sécurisée.</p>
        </header>

        <div className="action-cards">
          <div className="card">
            <h2>Créer une Session de Partage</h2>
            <p className="description">
              Lancez une nouvelle session et partagez un dossier de votre ordinateur.
            </p>
            <div className="input-group">
              <label htmlFor="folder-path-create">Dossier à partager :</label>
              <input
                id="folder-path-create"
                type="text"
                readOnly
                value={sharedFolderPath}
                placeholder="Cliquez sur le bouton pour choisir..."
              />
              <button className="button-outline" onClick={() => selectFolder(setSharedFolderPath)}>
                Choisir un dossier
              </button>
            </div>
            <button onClick={() => handleSessionAttempt('create')}>Démarrer la session</button>
          </div>

          <div className="card">
            <h2>Rejoindre une Session</h2>
            <p className="description">
              Connectez-vous à une session existante pour synchroniser un dossier.
            </p>
            <div className="input-group">
              <label htmlFor="remote-addr">Adresse du pair distant :</label>
              <input
                id="remote-addr"
                type="text"
                value={remoteAddr}
                onChange={(e) => setRemoteAddr(e.target.value)}
                placeholder="Collez l'adresse ici..."
              />
            </div>
            <div className="input-group">
              <label htmlFor="folder-path-join">Enregistrer le dossier dans :</label>
              <input
                id="folder-path-join"
                type="text"
                readOnly
                value={localPath}
                placeholder="Cliquez sur le bouton pour choisir..."
              />
              <button className="button-outline" onClick={() => selectFolder(setLocalPath)}>
                Choisir un emplacement
              </button>
            </div>
            <button onClick={() => handleSessionAttempt('join')}>Rejoindre</button>
          </div>
        </div>
      </div>
    </>
  );
}

export default App;
