export type AuthTokens = {
  access_token: string;
  refresh_token: string;
};

export type AuthUser = {
  id: string;
  email: string | null;
  phone: string | null;
  username: string;
  displayName: string;
  avatarUrl: string | null;
  isVerified: boolean;
  createdAt: Date;
};

export type AuthResponse = AuthTokens & {
  user: AuthUser;
  message: string;
  isNewUser?: boolean;
  requires2FA?: boolean;
  tempToken?: string;
};

export type Auth2FAChallenge = {
  requires2FA: true;
  message: string;
  tempToken: string;
};
