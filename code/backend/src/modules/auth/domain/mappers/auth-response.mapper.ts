import { User } from '@prisma/client';
import { AuthResponse, AuthTokens } from '../contracts/auth.contract';

export function mapAuthUser(
  user: Partial<User> & { id: string },
): AuthResponse['user'] {
  return {
    id: user.id,
    email: user.email ?? null,
    phone: user.phone ?? null,
    username: user.username ?? '',
    displayName: user.displayName ?? '',
    avatarUrl: user.avatarUrl ?? null,
    isVerified: user.isVerified ?? false,
    createdAt: user.createdAt ?? new Date(),
  };
}

export function mapAuthResponse(
  tokens: AuthTokens,
  user: Partial<User> & { id: string },
  message: string,
  isNewUser = false,
): AuthResponse {
  return {
    ...tokens,
    user: mapAuthUser(user),
    message,
    isNewUser,
  };
}
