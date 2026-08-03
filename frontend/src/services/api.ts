import axios from 'axios';
import { Listing, ListingQuery } from '../schema/listing';
import {
  Criteria,
  Filter,
  FilterCreate,
  FilterFormValue,
} from '../schema/filter';

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

// The name POST /filters/ stores when the form carries none. DL-366
export const DEFAULT_FILTER_NAME = 'Saved filter';

// The comparison each UI key prefix means on the wire. A key with neither
// prefix compares for equality on the key itself. DL-366
const RANGE_OPERATORS: ReadonlyArray<[string, string]> = [
  ['min', 'gte'],
  ['max', 'lte'],
];

const criterionFromEntry = (key: string, value: string | number): Criteria => {
  for (const [prefix, operator] of RANGE_OPERATORS) {
    if (key.startsWith(prefix) && key.length > prefix.length) {
      const named = key.slice(prefix.length);
      return {
        field: named.charAt(0).toLowerCase() + named.slice(1),
        operator,
        value: String(value),
      };
    }
  }
  return { field: key, operator: 'eq', value: String(value) };
};

// SEC-05: builds the allow-list POST /filters/ declares, and nothing else.
// Maps the UI model, which keys criteria by input name, onto the wire body,
// which carries field, operator and value triples. DL-366
export const toFilterCreate = (value: FilterFormValue): FilterCreate => {
  const submitted = value.criteria;
  const criteria: Criteria[] = Array.isArray(submitted)
    ? submitted.map(({ field, operator, value: text }) => ({
        field,
        operator,
        value: String(text),
      }))
    : Object.entries(submitted)
        .filter(([, entry]) => entry !== '' && entry !== null &&
          entry !== undefined)
        .map(([key, entry]) => criterionFromEntry(key, entry));

  const name = typeof value.name === 'string' && value.name.trim() !== ''
    ? value.name
    : DEFAULT_FILTER_NAME;

  return { name, criteria };
};

export const createFilter = async (
  filter: FilterFormValue
): Promise<Filter> => {
  try {
    const endpoint = `${API_BASE_URL}/filters/`;
    // SEC-05: sends the allow-list only; a server-owned key is refused
    const body: FilterCreate = toFilterCreate(filter);
    const response = await axios.post<Filter>(endpoint, body);
    return response.data;
  } catch (error) {
    console.error('Error creating filter:', error);
    throw error;
  }
};
