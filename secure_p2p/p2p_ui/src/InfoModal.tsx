import React from 'react';

interface InfoModalProps {
  isOpen: boolean;
  title: string;
  data: any[];
  onClose: () => void;
}

const InfoModal: React.FC<InfoModalProps> = ({ isOpen, title, data, onClose }) => {
  if (!isOpen) {
    return null;
  }

  return (
    <div className="modal-backdrop">
      <div className="modal-content info-modal">
        <h2>{title}</h2>
        <div className="info-content">
          {data.length === 0 ? (
            <p>Aucune donnée à afficher.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  {Object.keys(data[0]).map((key) => <th key={key}>{key}</th>)}
                </tr>
              </thead>
              <tbody>
                {data.map((item, index) => (
                  <tr key={index}>
                    {Object.values(item).map((val, i) => <td key={i}>{val as any}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        <div className="modal-actions">
          <button onClick={onClose}>Fermer</button>
        </div>
      </div>
    </div>
  );
};

export default InfoModal;
