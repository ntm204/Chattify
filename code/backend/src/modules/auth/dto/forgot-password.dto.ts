import { IsNotEmpty, IsString, MaxLength } from 'class-validator';
import { Transform } from 'class-transformer';
import { AuthUtils } from '../../../core/utils/auth.util';

export class ForgotPasswordDto {
  @Transform(({ value, obj }: { value: string; obj?: { email?: string } }) =>
    AuthUtils.normalizeIdentifier(value || obj?.email || ''),
  )
  @IsString()
  @IsNotEmpty({ message: 'Email hoặc Số điện thoại không được để trống' })
  @MaxLength(100)
  identifier: string;
}
