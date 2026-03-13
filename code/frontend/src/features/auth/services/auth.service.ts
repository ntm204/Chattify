import { axiosInstance } from '@/lib/axios';
import type { AxiosResponse } from 'axios';
import { AuthResponse } from '../interfaces/auth.interface';

export const authService = {
  login: async (credentials: Record<string, string>): Promise<AxiosResponse<AuthResponse>> => {
    return axiosInstance.post('/auth/login', credentials);
  },

  register: async (data: Record<string, string>): Promise<AxiosResponse<AuthResponse>> => {
    return axiosInstance.post('/auth/register', data);
  },

  forgotPassword: async (email: string): Promise<AxiosResponse> => {
    return axiosInstance.post('/auth/forgot-password', { email });
  },

  resetPassword: async (data: Record<string, string>): Promise<AxiosResponse> => {
    return axiosInstance.post('/auth/reset-password', data);
  },

  verifyEmail: async (data: Record<string, string>): Promise<AxiosResponse> => {
    return axiosInstance.post('/auth/verify-email', data);
  },

  logout: async (): Promise<AxiosResponse> => {
    return axiosInstance.post('/auth/logout');
  },
};
