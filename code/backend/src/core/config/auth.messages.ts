export const AUTH_MESSAGES = {
  // --- Controllers ---
  VERIFY_EMAIL_SUCCESS: 'Xác thực thành công',
  VERIFY_PHONE_SUCCESS: 'Xác thực số điện thoại thành công',
  LOGIN_SUCCESS: 'Đăng nhập thành công',
  REFRESH_TOKEN_NOT_FOUND: 'Không tìm thấy Refresh Token trong Cookie',
  REFRESH_TOKEN_SUCCESS: 'Làm mới Token thành công',
  LOGOUT_SUCCESS: 'Đăng xuất thành công',
  SESSION_NOT_FOUND: 'Phiên không tồn tại',
  SESSION_REVOKE_SUCCESS: 'Đã đăng xuất thiết bị',
  REFRESH_TOKEN_REUSE_DETECTED:
    'Phát hiện token cũ, tất cả phiên đã bị đăng xuất',
  REFRESH_TOKEN_INVALID: 'Token không hợp lệ',
  SESSION_EXPIRED: 'Phiên đã hết hạn',

  // --- AuthService ---
  REGISTER_SUCCESS: 'Đăng ký thành công! Vui lòng kiểm tra mã xác thực 6 số.',
  ACCOUNT_NOT_FOUND_OR_DELETED: 'Tài khoản không tồn tại hoặc đã bị xoá.',
  INVALID_CREDENTIALS_WARNING:
    'Email hoặc mật khẩu không chính xác. Cảnh báo: Bạn sắp bị khóa tài khoản tạm thời nếu tiếp tục nhập sai!',
  INVALID_CREDENTIALS: 'Email hoặc mật khẩu không chính xác',
  VERIFY_EMAIL_REQUIRED: 'Vui lòng xác thực Email trước khi đăng nhập!',
  VERIFY_PHONE_REQUIRED: 'Vui lòng xác thực số điện thoại trước khi đăng nhập!',
  TFA_REQUIRED: 'Vui lòng nhập mã Google Authenticator',
  TFA_TEMP_TOKEN_INVALID:
    'Phiên đăng nhập thời gian thực (2FA) không hợp lệ hoặc đã hết hạn.',
  TFA_NOT_ENABLED: 'Chưa kích hoạt 2FA hoặc người dùng không có 2FA.',
  USER_NOT_FOUND: 'Người dùng không tồn tại',
  EMAIL_REQUIRED: 'Vui lòng cung cấp email',
  IDENTIFIER_REQUIRED: 'Vui lòng cung cấp Email hoặc Số điện thoại',
  PHONE_LOGIN_REQUIRED: 'Vui lòng đăng nhập bằng Số điện thoại + OTP',
  REGISTER_PHONE_SUCCESS: 'Đăng ký bằng số điện thoại thành công',
  LOGIN_PHONE_SUCCESS: 'Đăng nhập bằng số điện thoại thành công',
  CHANGE_EMAIL_OTP_SENT: 'OTP đã được gửi đến email mới',
  CHANGE_EMAIL_SUCCESS: 'Đổi email thành công',
  CHANGE_PHONE_OTP_SENT: 'OTP đã được gửi đến số điện thoại mới',
  CHANGE_PHONE_SUCCESS: 'Đổi số điện thoại thành công',
  OTP_SENT_GENERIC:
    'Mã xác thực đã được gửi. Vui lòng kiểm tra hộp thư hoặc tin nhắn điện thoại.',

  // --- OtpService ---
  OTP_COOLDOWN: (ttl: number) =>
    `Vui lòng đợi ${ttl} giây trước khi yêu cầu gửi lại OTP.`,
  OTP_DAILY_LIMIT: (limit: number) =>
    `Bạn đã vượt quá giới hạn gửi OTP trong ngày (tối đa ${limit} lần). Vui lòng thử lại vào ngày mai.`,
  OTP_INVALID_OR_EXPIRED: 'Mã OTP không chính xác hoặc đã hết hạn',
  OTP_MAX_ATTEMPTS:
    'Bạn đã nhập sai OTP quá nhiều lần. Mã OTP đã bị hủy để bảo mật.',

  // --- PasswordService ---
  FORGOT_PASSWORD_GENERIC:
    'Nếu định danh tồn tại trong hệ thống, hướng dẫn khôi phục mật khẩu sẽ được gửi đến bạn.',
  RESET_OTP_INVALID: 'Mã OTP không hợp lệ hoặc đã hết hạn.',
  RESET_PASSWORD_SUCCESS: 'Mật khẩu đã được đặt lại thành công.',
  OLD_PASSWORD_INCORRECT: 'Mật khẩu cũ không chính xác',
  CHANGE_PASSWORD_SUCCESS:
    'Đổi mật khẩu thành công. Các thiết bị khác đã bị đăng xuất.',
  PASSWORD_PWNED_ERROR:
    'Mật khẩu này đã bị rò rỉ trong các vụ hack trước đó (theo HaveIBeenPwned). Vui lòng chọn mật khẩu khác để bảo vệ tài khoản.',
  PASSWORD_REUSE_ERROR:
    'Bạn không được sử dụng lại mật khẩu cũ. Vui lòng chọn một mật khẩu mới hoàn toàn.',

  // --- TwoFactorService ---
  TFA_ENABLE_SUCCESS: 'Xác minh và bật 2FA thành công!',
  TFA_DISABLE_SUCCESS: 'Đã tắt 2FA thành công!',
  TFA_CODE_INCORRECT: (attemptsLeft: number) =>
    `Mã 2FA không chính xác! Bạn còn ${attemptsLeft} lần thử.`,
  TFA_CODE_INCORRECT_WAIT: (maxAttempts: number) =>
    `Bạn đã nhập sai mã 2FA quá ${maxAttempts} lần. Vui lòng thử lại sau 5 phút!`,

  // --- LockoutService ---
  ACCOUNT_LOCKED: (delayTime: string) =>
    `Tài khoản của bạn đã bị khóa tạm thời do nhập sai quá nhiều lần. Vui lòng thử lại sau ${delayTime}.`,
  IP_LOCKED: (delayTime: string) =>
    `IP của bạn đã bị chặn tạm thời do phát hiện hành vi đáng ngờ. Vui lòng thử lại sau ${delayTime}.`,
} as const;
