import React, { useState, useEffect } from 'react';
import ListingCard from 'frontend/src/components/ListingCard';
import QuickSearchForm from 'frontend/src/components/QuickSearchForm';
import { fetchFeaturedListings } from 'frontend/src/services/api';

const HomePage: React.FC = () => {
  const [featuredListings, setFeaturedListings] = useState([]);

  useEffect(() => {
    const loadFeaturedListings = async () => {
      try {
        const listings = await fetchFeaturedListings();
        setFeaturedListings(listings);
      } catch (error) {
        console.error('Error fetching featured listings:', error);
        // HUMAN ASSISTANCE NEEDED
        // Consider implementing proper error handling and user feedback
      }
    };

    loadFeaturedListings();
  }, []);

  return (
    <div className="home-page">
      <h1>Welcome to Our Property Listing Platform</h1>
      
      <section className="quick-search">
        <h2>Quick Search</h2>
        <QuickSearchForm />
      </section>

      <section className="featured-listings">
        <h2>Featured Listings</h2>
        <div className="listing-grid">
          {featuredListings.map((listing) => (
            <ListingCard key={listing.id} listing={listing} />
          ))}
        </div>
      </section>
    </div>
  );
};

export default HomePage;