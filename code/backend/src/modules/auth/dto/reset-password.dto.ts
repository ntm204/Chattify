import {
  IsNotEmpty,
  IsString,
  Length,
  Matches,
  MaxLength,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { AuthUtils } from '../../../core/utils/auth.util';

export class ResetPasswordDto {
  @Transform(({ value, obj }: { value: string; obj?: { email?: string } }) =>
    AuthUtils.normalizeIdentifier(value || obj?.email || ''),
  )
  @IsString()
  @IsNotEmpty({ message: 'Email hoặc Số điện thoại không được để trống' })
  @MaxLength(100)
  identifier: string;

  @Length(6, 6, { message: 'Mã OTP phải bao gồm đúng 6 ký tự' })
  @Matches(/^\d{6}$/, { message: 'Mã OTP chỉ được chứa chữ số' })
  @IsNotEmpty({ message: 'Không được để trống mã OTP' })
  otp: string;

  @IsNotEmpty({ message: 'Mật khẩu mới không được để trống' })
  @Length(8, 50, { message: 'Mật khẩu phải từ 8 đến 50 ký tự' })
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Mật khẩu quá yếu (cần chữ hoa, thường và số/kí tự đặc biệt)',
  })
  newPassword: string;
}
