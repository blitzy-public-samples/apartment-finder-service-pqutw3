import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import ListingTable from 'frontend/src/components/ListingTable';
import FilterForm from 'frontend/src/components/FilterForm';
import { searchListings } from 'frontend/src/services/api';
import { setFilter } from 'frontend/src/store/actions/filterActions';

// HUMAN ASSISTANCE NEEDED
// The following component may need additional refinement for production readiness.
// Please review and adjust as necessary, particularly error handling and loading states.

const SearchResultsPage: React.FC = () => {
  const [searchResults, setSearchResults] = useState([]);
  const dispatch = useDispatch();
  const currentFilter = useSelector((state: any) => state.filter);

  useEffect(() => {
    const fetchSearchResults = async () => {
      try {
        const results = await searchListings(currentFilter);
        setSearchResults(results);
      } catch (error) {
        console.error('Error fetching search results:', error);
        // TODO: Implement proper error handling
      }
    };

    fetchSearchResults();
  }, [currentFilter]);

  const handleFilterChange = (newFilter: any) => {
    dispatch(setFilter(newFilter));
  };

  return (
    <div className="search-results-page">
      <h1>Search Results</h1>
      <FilterForm currentFilter={currentFilter} onFilterChange={handleFilterChange} />
      <ListingTable listings={searchResults} />
    </div>
  );
};

export default SearchResultsPage;