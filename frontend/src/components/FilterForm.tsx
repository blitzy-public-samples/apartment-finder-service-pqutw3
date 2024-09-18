import React, { useState } from 'react';
import { Filter } from 'frontend/src/schema/filter';
import { createFilter, updateFilter } from 'frontend/src/services/api';

// HUMAN ASSISTANCE NEEDED
// The confidence level is below 0.8, so this component may need review and improvements.
// Please check the implementation and make necessary adjustments.

interface FilterFormProps {
  initialFilter?: Filter;
  onSubmit: (filter: Filter) => void;
}

const FilterForm: React.FC<FilterFormProps> = ({ initialFilter, onSubmit }) => {
  const [filter, setFilter] = useState<Filter>(initialFilter || {
    zipCodes: [],
    criteria: {},
  });

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFilter((prevFilter) => ({
      ...prevFilter,
      [name]: value,
    }));
  };

  const handleZipCodeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const zipCodes = e.target.value.split(',').map((zip) => zip.trim());
    setFilter((prevFilter) => ({
      ...prevFilter,
      zipCodes,
    }));
  };

  const handleCriteriaChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFilter((prevFilter) => ({
      ...prevFilter,
      criteria: {
        ...prevFilter.criteria,
        [name]: value,
      },
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      let updatedFilter: Filter;
      if (initialFilter) {
        updatedFilter = await updateFilter(filter);
      } else {
        updatedFilter = await createFilter(filter);
      }
      onSubmit(updatedFilter);
    } catch (error) {
      console.error('Error submitting filter:', error);
      // TODO: Add proper error handling
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label htmlFor="zipCodes">Zip Codes (comma-separated):</label>
        <input
          type="text"
          id="zipCodes"
          name="zipCodes"
          value={filter.zipCodes.join(', ')}
          onChange={handleZipCodeChange}
        />
      </div>
      <div>
        <label htmlFor="minPrice">Minimum Price:</label>
        <input
          type="number"
          id="minPrice"
          name="minPrice"
          value={filter.criteria.minPrice || ''}
          onChange={handleCriteriaChange}
        />
      </div>
      <div>
        <label htmlFor="maxPrice">Maximum Price:</label>
        <input
          type="number"
          id="maxPrice"
          name="maxPrice"
          value={filter.criteria.maxPrice || ''}
          onChange={handleCriteriaChange}
        />
      </div>
      {/* Add more criteria inputs as needed */}
      <button type="submit">{initialFilter ? 'Update' : 'Create'} Filter</button>
    </form>
  );
};

export default FilterForm;