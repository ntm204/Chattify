import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
  IsOptional,
} from 'class-validator';
import { Transform } from 'class-transformer';

export class LoginDto {
  @Transform(({ value }: { value: string }) => value?.toLowerCase().trim())
  @IsEmail({}, { message: 'Định dạng email không hợp lệ' })
  @IsNotEmpty()
  @MaxLength(100)
  email: string;

  @IsString()
  @IsNotEmpty({ message: 'Mật khẩu không được để trống' })
  @MaxLength(100)
  password: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  deviceInfo?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  ipAddress?: string;
}
