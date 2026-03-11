import { IsNotEmpty, IsString, Length } from 'class-validator';

export class Verify2FADto {
  @IsNotEmpty({ message: 'Temp Token không được để trống' })
  @IsString()
  tempToken: string;

  @IsNotEmpty({ message: 'Mã 2FA không được để trống' })
  @IsString()
  @Length(6, 6, { message: 'Mã 2FA phải bao gồm đúng 6 chữ số' })
  code: string;
}
