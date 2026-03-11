import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

export class Toggle2FACodeDto {
  @IsNotEmpty({ message: 'Mã 2FA không được để trống' })
  @IsString()
  @Length(6, 6, { message: 'Mã 2FA phải bao gồm đúng 6 chữ số' })
  @Matches(/^\d{6}$/, { message: 'Mã 2FA chỉ được chứa chữ số' })
  code: string;
}
