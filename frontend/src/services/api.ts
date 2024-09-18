import axios from 'axios';
import { Listing } from 'frontend/src/schema/listing';
import { Filter } from 'frontend/src/schema/filter';
import { User } from 'frontend/src/schema/user';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;

export const fetchListings = async (filter: Filter): Promise<Listing[]> => {
  try {
    const endpoint = `${API_BASE_URL}/listings`;
    const response = await axios.get(endpoint, { params: filter });
    return response.data as Listing[];
  } catch (error) {
    console.error('Error fetching listings:', error);
    throw error;
  }
};

export const createFilter = async (filter: Filter): Promise<Filter> => {
  try {
    const endpoint = `${API_BASE_URL}/filters`;
    const response = await axios.post(endpoint, filter);
    return response.data as Filter;
  } catch (error) {
    console.error('Error creating filter:', error);
    throw error;
  }
};

export const getUserProfile = async (): Promise<User> => {
  try {
    const endpoint = `${API_BASE_URL}/user/profile`;
    const response = await axios.get(endpoint);
    return response.data as User;
  } catch (error) {
    console.error('Error fetching user profile:', error);
    throw error;
  }
};