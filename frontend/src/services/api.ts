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

// SEC-08: the sanitized error envelope every route returns, carried to
// the caller. `status` and `detail` separate one failure from another,
// `fields` names the rejected input, `errorId` is the support handle and
// `retryAfter` is the SEC-07 throttle recovery hint. `isNetworkError`
// marks a request that never reached the server, so an outage can never
// be reported as a rejected credential.
export interface ApiError extends Error {
  status?: number;
  detail?: string;
  fields: string[];
  errorId?: string;
  retryAfter?: number;
  isNetworkError: boolean;
}

// SEC-08: preserves the envelope on the thrown error. A bare rethrown
// message would discard the status, the field list and the correlation
// identifier the server deliberately emits.
export const toApiError = (error: unknown, fallback: string): ApiError => {
  const response = (error as any)?.response;
  const body = response?.data;
  const detail = typeof body?.detail === 'string' ? body.detail : undefined;
  const header = response?.headers?.['retry-after'];
  const retryAfter = Number(header);
  const enriched = new Error(detail || fallback) as ApiError;
  enriched.status = response?.status;
  enriched.detail = detail;
  enriched.fields = Array.isArray(body?.fields) ? body.fields : [];
  enriched.errorId =
    typeof body?.error_id === 'string' ? body.error_id : undefined;
  enriched.retryAfter = Number.isFinite(retryAfter) ? retryAfter : undefined;
  enriched.isNetworkError = response === undefined;
  return enriched;
};

export const fetchListings = async (
  query: ListingQuery = {}
): Promise<Listing[]> => {
  try {
    const endpoint = `${API_BASE_URL}/listings/`;
    const response = await axios.get<Listing[]>(endpoint, { params: query });
    return response.data;
  } catch (error) {
    console.error('Error fetching listings:', error);
    throw toApiError(error, 'Loading the listings failed');
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
    throw toApiError(error, 'Creating the filter failed');
  }
};
