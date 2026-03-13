export interface User {
  id: string;
  email: string;
  name: string;
  username?: string;
  avatarUrl?: string | null;
  is2FAEnabled: boolean;
}

export interface AuthResponse {
  user: User;
  requires2FA?: boolean;
  twoFactorToken?: string;
}

export interface ApiError {
  message: string;
  error: string;
  statusCode: number;
}
