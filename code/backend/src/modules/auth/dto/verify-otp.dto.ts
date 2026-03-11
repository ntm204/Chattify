import {
  IsEmail,
  IsNotEmpty,
  Length,
  IsOptional,
  IsString,
} from 'class-validator';

export class VerifyOtpDto {
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
