import { User } from '@prisma/client';

export enum CreateUserStatus {
  CREATED = 'CREATED',
  EXISTS_UNVERIFIED = 'EXISTS_UNVERIFIED',
  EXISTS_VERIFIED = 'EXISTS_VERIFIED',
}

export interface CreateUserResult {
  user: User;
  status: CreateUserStatus;
}
