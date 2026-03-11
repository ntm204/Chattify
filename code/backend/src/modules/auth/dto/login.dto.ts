import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
  IsOptional,
} from 'class-validator';

export class LoginDto {
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
