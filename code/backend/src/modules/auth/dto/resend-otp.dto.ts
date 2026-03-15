import { IsNotEmpty, IsString, MaxLength } from 'class-validator';
import { Transform } from 'class-transformer';
import { AuthUtils } from '../../../core/utils/auth.util';

export class ResendOtpDto {
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
}
