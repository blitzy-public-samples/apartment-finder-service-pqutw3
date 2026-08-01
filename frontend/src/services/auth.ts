import axios from 'axios';
import { User } from '../schema/user';
import { API_BASE_URL } from './api';

export async function login(email: string, password: string): Promise<User> {
  try {
    const response = await axios.post(`${API_BASE_URL}/auth/login`, { email, password });
    // SEC-06: the session token stays in the HttpOnly cookie, never in browser storage (CWE-522)
    const { user } = response.data;
    return user;
  } catch (error) {
    throw new Error('Login failed');
  }
}

// SEC-06: clears the HttpOnly session cookie server-side (CWE-1004)
export async function logout(): Promise<void> {
  await axios.post(`${API_BASE_URL}/auth/logout`);
}