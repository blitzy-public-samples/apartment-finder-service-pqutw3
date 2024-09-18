import React, { useState } from 'react';
import { PayPalSubscriptionButton } from 'frontend/src/services/paypal';
import { createSubscription } from 'frontend/src/services/api';

// HUMAN ASSISTANCE NEEDED
// The following code may need refinement for production readiness.
// Please review and adjust as necessary, especially the modal styling and subscription options.

interface SubscriptionModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const SubscriptionModal: React.FC<SubscriptionModalProps> = ({ isOpen, onClose }) => {
  const [selectedPlan, setSelectedPlan] = useState<string | null>(null);

  const handleSubscriptionSuccess = async (details: any) => {
    try {
      await createSubscription(details);
      onClose();
    } catch (error) {
      console.error('Error creating subscription:', error);
      // TODO: Add proper error handling
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h2>Choose a Subscription Plan</h2>
        <div className="subscription-options">
          <button onClick={() => setSelectedPlan('monthly')}>Monthly Plan - $9.99/month</button>
          <button onClick={() => setSelectedPlan('yearly')}>Yearly Plan - $99.99/year</button>
        </div>
        {selectedPlan && (
          <PayPalSubscriptionButton
            plan={selectedPlan}
            onSuccess={handleSubscriptionSuccess}
          />
        )}
        <button onClick={onClose}>Close</button>
      </div>
    </div>
  );
};

export default SubscriptionModal;