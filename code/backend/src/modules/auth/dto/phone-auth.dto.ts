import {
  IsNotEmpty,
  IsString,
  IsOptional,
  MaxLength,
  Length,
  Matches,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { AuthUtils } from '../../../core/utils/auth.util';

export class SendPhoneOtpDto {
  @ApiProperty({
    example: '0912345678',
    description: 'Số điện thoại nhận mã OTP',
  })
  @Transform(({ value }: { value: string }) =>
    AuthUtils.normalizeIdentifier(value),
  )
  @IsString()
  @IsNotEmpty({ message: 'Số điện thoại không được để trống' })
  @MaxLength(20, { message: 'Số điện thoại không hợp lệ' })
  phoneNumber: string;
}

export class VerifyPhoneOtpDto {
  @ApiProperty({
    example: '0912345678',
    description: 'Số điện thoại đã nhận mã',
  })
  @Transform(({ value }: { value: string }) =>
    AuthUtils.normalizeIdentifier(value),
  )
  @IsString()
  @IsNotEmpty({ message: 'Số điện thoại không được để trống' })
  @MaxLength(20, { message: 'Số điện thoại không hợp lệ' })
  phoneNumber: string;

  @ApiProperty({
    example: '123456',
    description: 'Mã OTP 6 số',
  })
  @IsString()
  @IsNotEmpty({ message: 'Mã OTP không được để trống' })
  @Length(6, 6, { message: 'Mã OTP phải bao gồm đúng 6 chữ số' })
  @Matches(/^\d{6}$/, { message: 'Mã OTP chỉ được chứa chữ số' })
  otp: string;

  @IsOptional()
  @IsString()
  ipAddress?: string;

  @IsOptional()
  @IsString()
  deviceInfo?: string;
}
