import React, { useState } from 'react';
import { Listing } from 'frontend/src/schema/listing';
import { ListingCard } from 'frontend/src/components/ListingCard';

interface ListingTableProps {
  listings: Listing[];
}

const ListingTable: React.FC<ListingTableProps> = ({ listings }) => {
  const [sortColumn, setSortColumn] = useState<keyof Listing>('id');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');

  const handleSort = (column: keyof Listing) => {
    if (column === sortColumn) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const sortedListings = [...listings].sort((a, b) => {
    if (a[sortColumn] < b[sortColumn]) return sortDirection === 'asc' ? -1 : 1;
    if (a[sortColumn] > b[sortColumn]) return sortDirection === 'asc' ? 1 : -1;
    return 0;
  });

  return (
    <table>
      <thead>
        <tr>
          <th onClick={() => handleSort('id')}>ID</th>
          <th onClick={() => handleSort('title')}>Title</th>
          <th onClick={() => handleSort('price')}>Price</th>
          <th onClick={() => handleSort('location')}>Location</th>
          <th onClick={() => handleSort('bedrooms')}>Bedrooms</th>
          <th onClick={() => handleSort('bathrooms')}>Bathrooms</th>
        </tr>
      </thead>
      <tbody>
        {sortedListings.map((listing) => (
          <tr key={listing.id}>
            <td colSpan={6}>
              <ListingCard listing={listing} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};

export default ListingTable;