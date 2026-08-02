import axios from 'axios';
import { API_BASE_URL } from './api';

// AAP 0.8.3: the frozen POST /auth/login response body
export interface AuthSession {
  access_token: string;
  token_type: string;
}

export async function login(email: string, password: string): Promise<AuthSession> {
  try {
    const response = await axios.post(`${API_BASE_URL}/auth/login`, { email, password });
    // SEC-06: the session token stays in the HttpOnly cookie, never in browser storage (CWE-522)
    const { access_token, token_type } = response.data;
    return { access_token, token_type };
  } catch (error) {
    // HUMAN ASSISTANCE NEEDED
    // Error handling could be improved. Consider adding specific error types and messages.
    throw new Error('Login failed');
  }
}

// SEC-06: clears the HttpOnly session cookie server-side (CWE-1004)
export async function logout(): Promise<void> {
  await axios.post(`${API_BASE_URL}/auth/logout`);
}