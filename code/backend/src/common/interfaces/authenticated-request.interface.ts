import { Request } from 'express';

export interface AuthenticatedUser {
  id: string;
  email: string;
  username: string;
  displayName: string;
  avatarUrl: string | null;
  currentSessionId?: string;
}

export interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
}
