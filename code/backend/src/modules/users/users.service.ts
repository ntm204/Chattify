import {
  Injectable,
  ConflictException,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from '../../core/prisma/prisma.service';
import { Prisma } from '@prisma/client';
import { RegisterDto } from '../auth/dto/register.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';

@Injectable()
export class UsersService {
  /** Safe select fields for User to prevent leaking sensitive data */
  private readonly USER_PUBLIC_SELECT = {
    id: true,
    email: true,
    username: true,
    displayName: true,
    avatarUrl: true,
    createdAt: true,
  } as const;

  constructor(private readonly prisma: PrismaService) {}

  async createUser(data: RegisterDto, passwordHash: string) {
    const existingUser = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: data.email }, { username: data.username }],
      },
    });

    if (existingUser) {
      if (!existingUser.isVerified && existingUser.email === data.email) {
        // Allow re-registration to update info if not yet verified
        return this.prisma.user.update({
          where: { id: existingUser.id },
          data: {
            username: data.username,
            displayName: data.displayName,
            passwordHash,
          },
          select: this.USER_PUBLIC_SELECT,
        });
      }

      if (existingUser.email === data.email) {
        throw new ConflictException('Email này đã được sử dụng!');
      }
      throw new ConflictException('Username này đã tồn tại!');
    }

    try {
      return await this.prisma.user.create({
        data: {
          email: data.email,
          username: data.username,
          displayName: data.displayName,
          passwordHash,
        },
        select: this.USER_PUBLIC_SELECT,
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        const target = (error.meta?.target as string[]) || [];
        if (target.includes('email')) {
          throw new ConflictException('Email này đã được sử dụng!');
        }
        if (target.includes('username')) {
          throw new ConflictException('Username này đã tồn tại!');
        }
        throw new ConflictException(
          'Thông tin đăng ký đã tồn tại, vui lòng thử lại!',
        );
      }
      throw new InternalServerErrorException(
        'Lỗi hệ thống khi tạo tài khoản. Vui lòng thử lại sau.',
      );
    }
  }

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  async findById(id: string) {
    return this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
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
