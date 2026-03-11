import { IsEmail, IsNotEmpty, Length, Matches } from 'class-validator';
import { Transform } from 'class-transformer';

export class ResetPasswordDto {
  @Transform(({ value }: { value: string }) => value?.toLowerCase().trim())
  @IsEmail({}, { message: 'Định dạng email không hợp lệ' })
  @IsNotEmpty({ message: 'Email không được để trống' })
  email: string;

  @Length(6, 6, { message: 'Mã OTP phải bao gồm đúng 6 ký tự' })
  @IsNotEmpty({ message: 'Không được để trống mã OTP' })
  otp: string;

  @IsNotEmpty({ message: 'Mật khẩu mới không được để trống' })
  @Length(8, 50, { message: 'Mật khẩu phải từ 8 đến 50 ký tự' })
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Mật khẩu quá yếu (cần chữ hoa, thường và số/kí tự đặc biệt)',
  })
  newPassword: string;
}
