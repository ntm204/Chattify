import { Injectable, ConflictException } from '@nestjs/common';
import { PrismaService } from '../../core/prisma/prisma.service';
import { RegisterDto } from '../auth/dto/register.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async createUser(data: RegisterDto, passwordHash: string) {
    // Kiểm tra email hoặc username đã tồn tại chưa
    const existingUser = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: data.email }, { username: data.username }],
      },
    });

    if (existingUser) {
      if (!existingUser.isVerified && existingUser.email === data.email) {
        // Cho phép đăng ký lại nếu chưa xác thực (cập nhật thông tin mới nhất)
        return this.prisma.user.update({
          where: { id: existingUser.id },
          data: {
            username: data.username,
            displayName: data.displayName,
            passwordHash,
          },
          select: {
            id: true,
            email: true,
            username: true,
            displayName: true,
            avatarUrl: true,
            createdAt: true,
          },
        });
      }

      if (existingUser.email === data.email) {
        throw new ConflictException('Email này đã được sử dụng!');
      }
      throw new ConflictException('Username này đã tồn tại!');
    }

    // Tạo thư mục người dùng mới
    return this.prisma.user.create({
      data: {
        email: data.email,
        username: data.username,
        displayName: data.displayName,
        passwordHash,
      },
      select: {
        id: true,
        email: true,
        username: true,
        displayName: true,
        avatarUrl: true,
        createdAt: true,
      },
    });
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
