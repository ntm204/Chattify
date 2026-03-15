import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

export class Toggle2FACodeDto {
  @IsNotEmpty({ message: 'Mã 2FA không được để trống' })
  @IsString()
  @Length(6, 8, { message: 'Mã 2FA hoặc mã dự phòng không hợp lệ' })
  @Matches(/^(\d{6}|[A-Z0-9]{8})$/, {
    message: 'Mã 2FA gồm 6 chữ số hoặc mã dự phòng gồm 8 ký tự',
  })
  code: string;
}
