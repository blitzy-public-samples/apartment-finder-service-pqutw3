import axios from 'axios';
import { User } from '../schema/user';
import { API_BASE_URL } from './api';

export async function login(email: string, password: string): Promise<User> {
  try {
    const response = await axios.post(`${API_BASE_URL}/auth/login`, { email, password });
    // SEC-06: token moved to an HttpOnly cookie; removes it from script-readable storage
    const { user } = response.data;
    return user;
  } catch (error) {
    // HUMAN ASSISTANCE NEEDED
    // Error handling could be improved. Consider adding specific error types and messages.
    throw new Error('Login failed');
  }
}

export async function logout(): Promise<void> {
  // SEC-06: clears the HttpOnly cookie server-side
  await axios.post(`${API_BASE_URL}/auth/logout`);
}