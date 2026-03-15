import { IsNotEmpty, IsString, MaxLength } from 'class-validator';
import { Transform } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { AuthUtils } from '../../../core/utils/auth.util';

export class LoginDto {
  @ApiProperty({
    example: 'user@example.com hoặc +84912345678',
    description: 'Email hoặc Số điện thoại của người dùng',
  })
  @Transform(({ value, obj }: { value: string; obj?: { email?: string } }) =>
    AuthUtils.normalizeIdentifier(value || obj?.email || ''),
  )
  @IsString()
  @IsNotEmpty({ message: 'Email hoặc Số điện thoại không được để trống' })
  @MaxLength(100)
  identifier: string;

  @ApiProperty({
    example: 'password123',
    description: 'Mật khẩu người dùng',
  })
  @IsString()
  @IsNotEmpty({ message: 'Mật khẩu không được để trống' })
  @MaxLength(100, { message: 'Mật khẩu không được vượt quá 100 ký tự' })
  password: string;
}

export type LoginPayload = LoginDto & {
  ipAddress?: string;
  deviceInfo?: string;
};
