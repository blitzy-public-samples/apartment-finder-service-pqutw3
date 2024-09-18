import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { fetchListingDetails } from 'frontend/src/services/api';
import { ListingGallery } from 'frontend/src/components/ListingGallery';

interface ListingDetails {
  id: string;
  address: string;
  price: number;
  bedrooms: number;
  bathrooms: number;
  squareFootage: number;
  description: string;
  zillowLink: string;
  images: string[];
}

const ListingDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [listing, setListing] = useState<ListingDetails | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchListing = async () => {
      try {
        const data = await fetchListingDetails(id);
        setListing(data);
        setLoading(false);
      } catch (err) {
        setError('Failed to fetch listing details');
        setLoading(false);
      }
    };

    fetchListing();
  }, [id]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!listing) return <div>Listing not found</div>;

  return (
    <div className="listing-detail-page">
      <h1>{listing.address}</h1>
      <ListingGallery images={listing.images} />
      <div className="listing-info">
        <p>Price: ${listing.price.toLocaleString()}</p>
        <p>Bedrooms: {listing.bedrooms}</p>
        <p>Bathrooms: {listing.bathrooms}</p>
        <p>Square Footage: {listing.squareFootage} sq ft</p>
        <p>Description: {listing.description}</p>
      </div>
      <a href={listing.zillowLink} target="_blank" rel="noopener noreferrer">
        View on Zillow
      </a>
    </div>
  );
};

export default ListingDetailPage;