import { IsEmail, IsNotEmpty, IsString, Matches } from 'class-validator';

export class RequestChangeEmailDto {
  @IsEmail({}, { message: 'Email mới không hợp lệ.' })
  @IsNotEmpty({ message: 'Email mới không được để trống.' })
  newEmail: string;
}

export class VerifyChangeEmailDto {
  @IsEmail({}, { message: 'Email không hợp lệ.' })
  @IsNotEmpty({ message: 'Email không được để trống.' })
  email: string;

  @IsString()
  @IsNotEmpty({ message: 'Mã xác thực không được để trống.' })
  @Matches(/^\d{6}$/, { message: 'Mã xác thực phải là 6 chữ số.' })
  otp: string;
}

export class RequestChangePhoneDto {
  @IsNotEmpty({ message: 'Số điện thoại mới không được để trống.' })
  @Matches(/^\+?[1-9]\d{1,14}$/, {
    message: 'Số điện thoại phải theo định dạng quốc tế (VD: +84987654321).',
  })
  newPhone: string;
}

export class VerifyChangePhoneDto {
  @IsNotEmpty({ message: 'Số điện thoại không được để trống.' })
  @IsString()
  phone: string;

  @IsString()
  @IsNotEmpty({ message: 'Mã xác thực không được để trống.' })
  @Matches(/^\d{6}$/, { message: 'Mã xác thực phải là 6 chữ số.' })
  otp: string;
}
