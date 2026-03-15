import {
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../../core/prisma/prisma.service';
import { Prisma, User } from '@prisma/client';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { randomUUID } from 'crypto';

import {
  CreateUserResult,
  CreateUserStatus,
} from './interfaces/user.interface';

type CreateUserInput = {
  email: string;
  username: string;
  displayName: string;
};

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);
  /** Safe select fields for User to prevent leaking sensitive data */
  private readonly USER_PUBLIC_SELECT = {
    id: true,
    email: true,
    phone: true,
    username: true,
    displayName: true,
    avatarUrl: true,
    isVerified: true,
    createdAt: true,
  } as const;

  constructor(private readonly prisma: PrismaService) {}

  async createUser(
    data: CreateUserInput,
    passwordHash: string,
  ): Promise<CreateUserResult> {
    const existingUser = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: data.email }, { username: data.username }],
      },
    });

    if (existingUser) {
      if (!existingUser.isVerified && existingUser.email === data.email) {
        return {
          user: existingUser,
          status: CreateUserStatus.EXISTS_UNVERIFIED,
        };
      }
      return { user: existingUser, status: CreateUserStatus.EXISTS_VERIFIED };
    }

    try {
      return await this.prisma.$transaction(async (tx) => {
        const newUser = await tx.user.create({
          data: {
            email: data.email,
            username: data.username,
            displayName: data.displayName,
            passwordHash,
          },
        });

        await tx.passwordHistory.create({
          data: {
            userId: newUser.id,
            passwordHash,
          },
        });

        return { user: newUser, status: CreateUserStatus.CREATED };
      });
    } catch (error) {
      // Handle potential race conditions where user was created between findFirst and create
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        const reFoundUser = await this.prisma.user.findFirst({
          where: { OR: [{ email: data.email }, { username: data.username }] },
        });
        if (!reFoundUser) {
          throw new InternalServerErrorException(
            'Lỗi hệ thống khi tạo tài khoản.',
          );
        }
        return {
          user: reFoundUser,
          status: reFoundUser.isVerified
            ? CreateUserStatus.EXISTS_VERIFIED
            : CreateUserStatus.EXISTS_UNVERIFIED,
        };
      }
      throw new InternalServerErrorException('Lỗi hệ thống khi tạo tài khoản.');
    }
  }

  /**
   * Create a new user via Phone (Passwordless)
   */
  async createPhoneUser(phoneNumber: string): Promise<User> {
    const username = `user_${randomUUID().split('-')[0]}`;

    try {
      return await this.prisma.user.create({
        data: {
          phone: phoneNumber,
          email: null,
          username,
          displayName: `User ${phoneNumber.slice(-4)}`,
          passwordHash: null,
          isVerified: true,
        },
      });
    } catch (error) {
      this.logger.error('Error creating phone user', error);
      throw new InternalServerErrorException(
        'Lỗi hệ thống khi đăng ký bằng số điện thoại.',
      );
    }
  }

  async findByIdentifier(identifier: string) {
    return this.prisma.user.findFirst({
      where: {
        OR: [{ email: identifier }, { phone: identifier }],
      },
      select: {
        ...this.USER_PUBLIC_SELECT,
        isVerified: true,
      },
    });
  }

  async findByIdentifierWithPassword(identifier: string) {
    return this.prisma.user.findFirst({
      where: {
        OR: [{ email: identifier }, { phone: identifier }],
      },
    });
  }

  async markIdentifierVerified(identifier: string) {
    return this.prisma.user.updateMany({
      where: {
        OR: [{ email: identifier }, { phone: identifier }],
      },
      data: { isVerified: true },
    });
  }

  async findById(id: string) {
    return this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        phone: true,
        username: true,
        displayName: true,
        avatarUrl: true,
        status: true,
        lastSeen: true,
      },
    });
  }

  async updateProfile(userId: string, data: UpdateProfileDto) {
    return this.prisma.user.update({
      where: { id: userId },
      data,
      select: {
        id: true,
        email: true,
        username: true,
        displayName: true,
        avatarUrl: true,
        status: true,
      },
    });
  }
}
