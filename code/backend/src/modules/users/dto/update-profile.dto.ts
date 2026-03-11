import { IsOptional, IsString, IsUrl, MaxLength } from 'class-validator';

export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  @MaxLength(50, { message: 'Tên hiển thị quá dài' })
  displayName?: string;

  @IsOptional()
  @IsString()
  @IsUrl({}, { message: 'URL ảnh đại diện không hợp lệ' })
  @MaxLength(500, { message: 'URL ảnh đại diện quá dài' })
  avatarUrl?: string;
}
