import axios from 'axios';
import { User } from '../schema/user';
import { API_BASE_URL } from './api';

const TOKEN_KEY = 'auth_token';

export async function login(email: string, password: string): Promise<User> {
  try {
    const response = await axios.post(`${API_BASE_URL}/login`, { email, password });
    const { token, user } = response.data;
    localStorage.setItem(TOKEN_KEY, token);
    return user;
  } catch (error) {
    // HUMAN ASSISTANCE NEEDED
    // Error handling could be improved. Consider adding specific error types and messages.
    throw new Error('Login failed');
  }
}

export function logout(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}