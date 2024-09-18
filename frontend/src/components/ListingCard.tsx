import React from 'react';
import { Listing } from 'frontend/src/schema/listing';

const ListingCard: React.FC<{ listing: Listing }> = ({ listing }) => {
  const {
    id,
    address,
    rent,
    bedrooms,
    bathrooms,
    squareFootage,
    imageUrl,
    zillowLink
  } = listing;

  return (
    <div className="listing-card">
      <img src={imageUrl} alt={`Apartment at ${address}`} className="listing-image" />
      <div className="listing-details">
        <h2>{address}</h2>
        <p className="rent">${rent}/month</p>
        <div className="property-info">
          <span>{bedrooms} bed</span>
          <span>{bathrooms} bath</span>
          <span>{squareFootage} sqft</span>
        </div>
        <a href={zillowLink} target="_blank" rel="noopener noreferrer" className="zillow-link">
          View on Zillow
        </a>
      </div>
    </div>
  );
};

export default ListingCard;