import React, { useState } from 'react';

interface PasswordModalProps {
  isOpen: boolean;
  isNewKeypair: boolean;
  onSubmit: (password: string, confirm?: string) => void;
  onClose: () => void;
}

const PasswordModal: React.FC<PasswordModalProps> = ({ isOpen, isNewKeypair, onSubmit, onClose }) => {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');

  if (!isOpen) {
    return null;
  }

  const handleSubmit = () => {
    if (isNewKeypair) {
      if (password.length < 8) {
        setError('Le mot de passe doit faire au moins 8 caractères.');
        return;
      }
      if (password !== confirmPassword) {
        setError('Les mots de passe ne correspondent pas.');
        return;
      }
    }
    onSubmit(password, confirmPassword);
    setError('');
    setPassword('');
    setConfirmPassword('');
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-content">
        <h2>{isNewKeypair ? 'Créer un mot de passe' : 'Déverrouiller votre clé'}</h2>
        <p>
          {isNewKeypair
            ? 'Veuillez définir un mot de passe pour chiffrer votre clé d\'identité. Vous en aurez besoin pour vous connecter.'
            : 'Veuillez entrer votre mot de passe pour déchiffrer votre clé d\'identité.'}
        </p>

        <div className="input-group">
          <label htmlFor="password">Mot de passe :</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        {isNewKeypair && (
          <div className="input-group">
            <label htmlFor="confirm-password">Confirmer le mot de passe :</label>
            <input
              id="confirm-password"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>
        )}

        {error && <p className="error-message">{error}</p>}

        <div className="modal-actions">
          <button className="button-outline" onClick={onClose}>Annuler</button>
          <button onClick={handleSubmit}>Valider</button>
        </div>
      </div>
    </div>
  );
};

export default PasswordModal;
