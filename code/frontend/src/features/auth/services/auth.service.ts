import { axiosInstance } from '@/lib/axios';
// Import proper DTOs/types once defined, for now use generic objects
import type { AxiosResponse } from 'axios';

export const authService = {
  login: async (credentials: Record<string, string>): Promise<AxiosResponse> => {
    return axiosInstance.post('/auth/login', credentials);
  },

  register: async (data: Record<string, string>): Promise<AxiosResponse> => {
    return axiosInstance.post('/auth/register', data);
  },

  verifyEmail: async (data: Record<string, string>): Promise<AxiosResponse> => {
    return axiosInstance.post('/auth/verify-email', data);
  },

  logout: async (): Promise<AxiosResponse> => {
    return axiosInstance.post('/auth/logout');
  },
  
  // Future implementation endpoints
  // forgotPassword, resetPassword, changePassword, verify2FA
};
