import React, { useState, useEffect } from 'react';
import SubscriptionModal from 'frontend/src/components/SubscriptionModal';
import PayPalSubscriptionButton from 'frontend/src/services/paypal';
import { createSubscription } from 'frontend/src/services/api';

// HUMAN ASSISTANCE NEEDED
// The following component needs review for production readiness.
// Additional error handling, loading states, and user feedback mechanisms may be required.
// The subscription options and pricing should be fetched from an API or configuration file.

const SubscriptionPage: React.FC = () => {
  const [showModal, setShowModal] = useState(false);
  const [subscriptionPlan, setSubscriptionPlan] = useState<string | null>(null);

  const subscriptionOptions = [
    { id: 'basic', name: 'Basic Plan', price: 9.99 },
    { id: 'premium', name: 'Premium Plan', price: 19.99 },
  ];

  const handleSubscriptionCreation = async (paymentDetails: any) => {
    try {
      const response = await createSubscription(subscriptionPlan!, paymentDetails);
      if (response.success) {
        setShowModal(true);
      } else {
        console.error('Subscription creation failed:', response.error);
        // TODO: Add user-friendly error handling
      }
    } catch (error) {
      console.error('Error creating subscription:', error);
      // TODO: Add user-friendly error handling
    }
  };

  return (
    <div className="subscription-page">
      <h1>Choose Your Subscription Plan</h1>
      <div className="subscription-options">
        {subscriptionOptions.map((option) => (
          <div key={option.id} className="subscription-option">
            <h2>{option.name}</h2>
            <p>${option.price.toFixed(2)} / month</p>
            <button onClick={() => setSubscriptionPlan(option.id)}>Select</button>
          </div>
        ))}
      </div>
      {subscriptionPlan && (
        <PayPalSubscriptionButton
          plan={subscriptionPlan}
          onSuccess={handleSubscriptionCreation}
          onError={(error) => console.error('PayPal error:', error)}
        />
      )}
      {showModal && (
        <SubscriptionModal
          onClose={() => setShowModal(false)}
          plan={subscriptionPlan!}
        />
      )}
    </div>
  );
};

export default SubscriptionPage;