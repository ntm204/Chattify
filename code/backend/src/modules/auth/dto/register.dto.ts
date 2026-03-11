import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MinLength,
  Matches,
  MaxLength,
} from 'class-validator';
import { Transform } from 'class-transformer';

export class RegisterDto {
  @IsString()
  @IsNotEmpty()
  @Matches(/^[a-zA-Z0-9_]+$/, {
    message: 'Username chỉ được chứa chữ cái không dấu, số và gạch dưới (_)',
  })
  @MinLength(3, { message: 'Username phải từ 3 ký tự trở lên' })
  @MaxLength(20, { message: 'Username không vượt quá 20 ký tự' })
  username: string;

  @Transform(({ value }: { value: string }) => value?.toLowerCase().trim())
  @IsEmail({}, { message: 'Định dạng email không hợp lệ' })
  @IsNotEmpty()
  @MaxLength(100, { message: 'Email không được vượt quá 100 ký tự' })
  email: string;

  @IsString()
  @MinLength(8, { message: 'Mật khẩu phải dài ít nhất 8 ký tự' })
  @MaxLength(100, { message: 'Mật khẩu không được vượt quá 100 ký tự' })
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message:
      'Mật khẩu quá yếu (Yêu cầu ít nhất 1 chữ hoa, 1 chữ thường, và 1 số hoặc ký tự đặc biệt)',
  })
  password: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(50, { message: 'Tên hiển thị không được vượt quá 50 ký tự' })
  displayName: string;
}
