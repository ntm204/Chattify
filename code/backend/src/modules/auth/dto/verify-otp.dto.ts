import { IsEmail, IsNotEmpty, Length, Matches } from 'class-validator';
import { Transform } from 'class-transformer';

export class VerifyOtpDto {
  @Transform(({ value }: { value: string }) => value?.toLowerCase().trim())
  @IsEmail({}, { message: 'Định dạng email không hợp lệ' })
  @IsNotEmpty()
  email: string;

  @Length(6, 6, { message: 'Mã OTP phải bao gồm đúng 6 ký tự' })
  @Matches(/^\d{6}$/, { message: 'Mã OTP chỉ được chứa chữ số' })
  @IsNotEmpty({ message: 'Không được để trống mã OTP' })
  otp: string;
}

export type VerifyOtpPayload = VerifyOtpDto & {
  ipAddress?: string;
  deviceInfo?: string;
};
