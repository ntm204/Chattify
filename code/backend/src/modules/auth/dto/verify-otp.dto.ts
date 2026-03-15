import {
  IsNotEmpty,
  IsString,
  Length,
  Matches,
  MaxLength,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { AuthUtils } from '../../../core/utils/auth.util';

export class VerifyOtpDto {
  @Transform(
    ({
      value,
      obj,
    }: {
      value: string;
      obj?: { email?: string; phoneNumber?: string };
    }) =>
      AuthUtils.normalizeIdentifier(
        value || obj?.email || obj?.phoneNumber || '',
      ),
  )
  @IsNotEmpty({ message: 'Email hoặc số điện thoại không được để trống' })
  @IsString()
  @MaxLength(100)
  identifier: string;

  @Length(6, 6, { message: 'Mã OTP phải bao gồm đúng 6 ký tự' })
  @Matches(/^\d{6}$/, { message: 'Mã OTP chỉ được chứa chữ số' })
  @IsNotEmpty({ message: 'Không được để trống mã OTP' })
  otp: string;
}

export type VerifyOtpPayload = VerifyOtpDto & {
  ipAddress?: string;
  deviceInfo?: string;
};
