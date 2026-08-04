import axios from 'axios';
import { API_BASE_URL, ApiError, toApiError } from './api';

// The frozen POST /auth/login response body
export interface AuthSession {
  access_token: string;
  token_type: string;
}

// SEC-07: the login request currently outstanding, with a fingerprint of
// the submitted credentials. A repeated submit of the same credentials
// re-uses it instead of spending another attempt from the throttle
// allowance (CWE-307).
let outstanding: { key: string; request: Promise<AuthSession> } | null = null;

// SEC-07: true while a login request is outstanding, so a caller can
// disable its control rather than let one gesture fire several attempts
export function isLoginPending(): boolean {
  return outstanding !== null;
}

async function requestSession(
  email: string,
  password: string
): Promise<AuthSession> {
  try {
    const response = await axios.post(`${API_BASE_URL}/auth/login`, {
      email,
      password,
    });
    // SEC-06: the client returns the frozen response body but does not persist
    // its token; browser authentication uses the HttpOnly cookie (CWE-1004)
    const { access_token, token_type } = response.data;
    return { access_token, token_type };
  } catch (error) {
    // SEC-08: carries the server's sanitized envelope - status, detail,
    // fields, error_id and the SEC-07 Retry-After - to the caller
    throw toApiError(error, 'Login failed');
  }
}

export async function login(
  email: string,
  password: string
): Promise<AuthSession> {
  const key = `${email}\u0000${password}`;
  if (outstanding !== null && outstanding.key === key) {
    return outstanding.request;
  }
  const request = requestSession(email, password);
  outstanding = { key, request };
  try {
    return await request;
  } finally {
    if (outstanding !== null && outstanding.request === request) {
      outstanding = null;
    }
  }
}

// SEC-06: clears the HttpOnly session cookie server-side (CWE-1004).
// Resolves true only when the server confirmed the clear. Script cannot
// read an HttpOnly cookie, so this result is a caller's only signal that
// the session ended; false means it is still live.
export async function logout(): Promise<boolean> {
  try {
    await axios.post(`${API_BASE_URL}/auth/logout`);
    return true;
  } catch (error) {
    const failure: ApiError = toApiError(error, 'Logout failed');
    console.error(
      'Error logging out:',
      failure.message,
      failure.errorId || ''
    );
    return false;
  }
}