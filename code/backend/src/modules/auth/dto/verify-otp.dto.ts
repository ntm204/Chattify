import {
  IsEmail,
  IsNotEmpty,
  Length,
  IsOptional,
  IsString,
} from 'class-validator';
import { Transform } from 'class-transformer';

export class VerifyOtpDto {
  @Transform(({ value }: { value: string }) => value?.toLowerCase().trim())
  @IsEmail({}, { message: 'Định dạng email không hợp lệ' })
  @IsNotEmpty()
  email: string;

  @Length(6, 6, { message: 'Mã OTP phải bao gồm đúng 6 ký tự' })
  @IsNotEmpty({ message: 'Không được để trống mã OTP' })
  otp: string;

  @IsString()
  @IsOptional()
  deviceInfo?: string;

  @IsString()
  @IsOptional()
  ipAddress?: string;
}
