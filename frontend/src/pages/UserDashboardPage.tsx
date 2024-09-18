import React, { useState, useEffect } from 'react';
import SavedFilters from 'frontend/src/components/SavedFilters';
import SubscriptionStatus from 'frontend/src/components/SubscriptionStatus';
import { fetchUserProfile } from 'frontend/src/services/api';

// HUMAN ASSISTANCE NEEDED
// The following component may need additional error handling, loading states, and possibly more user information display. Please review and enhance as necessary.

const UserDashboardPage: React.FC = () => {
  const [userProfile, setUserProfile] = useState<any>(null);

  useEffect(() => {
    const loadUserProfile = async () => {
      try {
        const profile = await fetchUserProfile();
        setUserProfile(profile);
      } catch (error) {
        console.error('Failed to fetch user profile:', error);
        // TODO: Handle error state
      }
    };

    loadUserProfile();
  }, []);

  if (!userProfile) {
    return <div>Loading...</div>;
  }

  return (
    <div className="user-dashboard">
      <h1>User Dashboard</h1>
      <div className="user-info">
        <h2>Welcome, {userProfile.name}</h2>
        <p>Email: {userProfile.email}</p>
        {/* Add more user information as needed */}
      </div>
      <SavedFilters />
      <SubscriptionStatus />
    </div>
  );
};

export default UserDashboardPage;