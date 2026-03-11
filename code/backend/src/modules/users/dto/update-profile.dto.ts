import { IsOptional, IsString, MaxLength } from 'class-validator';

export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  @MaxLength(50, { message: 'Tên hiển thị quá dài' })
  displayName?: string;

  @IsOptional()
  @IsString()
  avatarUrl?: string;
}
