import axios from 'axios';
import { Listing, ListingQuery } from '../schema/listing';
import { Filter, FilterCreate } from '../schema/filter';
import { User } from '../schema/user';

export const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;
// SEC-06: sends the HttpOnly session cookie; no xsrf option is set
axios.defaults.withCredentials = true;

export const fetchListings = async (
  query: ListingQuery = {}
): Promise<Listing[]> => {
  try {
    const endpoint = `${API_BASE_URL}/listings/`;
    const response = await axios.get<Listing[]>(endpoint, { params: query });
    return response.data;
  } catch (error) {
    console.error('Error fetching listings:', error);
    throw error;
  }
};

export const createFilter = async (filter: FilterCreate): Promise<Filter> => {
  try {
    const endpoint = `${API_BASE_URL}/filters/`;
    // SEC-05: sends the allow-list only; a server-owned key is refused
    const body: FilterCreate = {
      name: filter.name,
      criteria: filter.criteria.map(({ field, operator, value }) => ({
        field,
        operator,
        value,
      })),
    };
    const response = await axios.post<Filter>(endpoint, body);
    return response.data;
  } catch (error) {
    console.error('Error creating filter:', error);
    throw error;
  }
};

export const getUserProfile = async (): Promise<User> => {
  try {
    const endpoint = `${API_BASE_URL}/user/profile`;
    const response = await axios.get<User>(endpoint);
    return response.data;
  } catch (error) {
    console.error('Error fetching user profile:', error);
    throw error;
  }
};
