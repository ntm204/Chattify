import axios, { AxiosResponse, AxiosError, InternalAxiosRequestConfig } from 'axios';

// Determine base URL depending on environment
const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000/api/v1';

export const axiosInstance = axios.create({
  baseURL: API_URL,
  withCredentials: true, // Crucial for sending HTTPOnly cookies (Access & Refresh tokens)
  headers: {
    'Content-Type': 'application/json',
  },
});

// Response interceptor to catch 401 Unauthorized errors and attempt token refresh
axiosInstance.interceptors.response.use(
  (response: AxiosResponse) => {
    return response;
  },
  async (error: AxiosError) => {
    // Add custom property `_retry` to config locally to avoid ts errors.
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    // If error is 401 and we haven't already retried this original request
    if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Attempt to refresh the token using the HTTPOnly refresh_token cookie
        // The backend `auth/refresh` endpoint expects the cookie and will issue a set-cookie header
        await axios.post(`${API_URL}/auth/refresh`, {}, { withCredentials: true });

        // If refresh is successful, retry the original request
        return axiosInstance(originalRequest);
      } catch (refreshError) {
        // Refresh token failed (expired or invalid)
        // Redirect to login page or handle global auth logout state here
        if (typeof window !== 'undefined') {
           window.location.href = '/login';
        }
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);
