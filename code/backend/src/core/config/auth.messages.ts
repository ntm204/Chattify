export const AUTH_MESSAGES = {
  // --- Controllers ---
  VERIFY_EMAIL_SUCCESS: 'Xác thực thành công',
  LOGIN_SUCCESS: 'Đăng nhập thành công',
  REFRESH_TOKEN_NOT_FOUND: 'Không tìm thấy Refresh Token trong Cookie',
  REFRESH_TOKEN_SUCCESS: 'Làm mới Token thành công',
  LOGOUT_SUCCESS: 'Đăng xuất thành công',

  // --- AuthService ---
  REGISTER_SUCCESS:
    'Đăng ký thành công! Vui lòng kiểm tra Email để nhận mã OTP 6 số.',
  ACCOUNT_NOT_FOUND_OR_DELETED: 'Tài khoản không tồn tại hoặc đã bị xoá.',
  INVALID_CREDENTIALS_WARNING:
    'Email hoặc mật khẩu không chính xác. Cảnh báo: Bạn sắp bị khóa tài khoản tạm thời nếu tiếp tục nhập sai!',
  INVALID_CREDENTIALS: 'Email hoặc mật khẩu không chính xác',
  VERIFY_EMAIL_REQUIRED: 'Vui lòng xác thực Email trước khi đăng nhập!',
  TFA_REQUIRED: 'Vui lòng nhập mã Google Authenticator',
  TFA_TEMP_TOKEN_INVALID:
    'Phiên đăng nhập thời gian thực (2FA) không hợp lệ hoặc đã hết hạn.',
  TFA_NOT_ENABLED: 'Chưa kích hoạt 2FA hoặc người dùng không có 2FA.',
  USER_NOT_FOUND: 'Người dùng không tồn tại',
  EMAIL_REQUIRED: 'Vui lòng cung cấp email',
  OTP_SENT_GENERIC:
    'Nếu email hợp lệ và chưa xác thực, mã OTP sẽ được gửi đến email của bạn.',

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
    'Nếu email tồn tại trong hệ thống, hướng dẫn khôi phục mật khẩu sẽ được gửi đến email của bạn.',
  RESET_OTP_INVALID: 'Mã OTP không hợp lệ hoặc đã hết hạn.',
  OLD_PASSWORD_INCORRECT: 'Mật khẩu cũ không chính xác',
  CHANGE_PASSWORD_SUCCESS:
    'Đổi mật khẩu thành công. Các thiết bị khác đã bị đăng xuất.',

  // --- TwoFactorService ---
  TFA_CODE_INCORRECT: (attemptsLeft: number) =>
    `Mã 2FA không chính xác! Bạn còn ${attemptsLeft} lần thử.`,
  TFA_CODE_INCORRECT_WAIT: (maxAttempts: number) =>
    `Bạn đã nhập sai mã 2FA quá ${maxAttempts} lần. Vui lòng thử lại sau 5 phút!`,

  // --- LockoutService ---
  ACCOUNT_LOCKED: (delayTime: string) =>
    `Tài khoản của bạn đã bị khóa tạm thời do nhập sai mật khẩu quá nhiều lần. Vui lòng thử lại sau ${delayTime}.`,
  IP_LOCKED: (delayTime: string) =>
    `IP của bạn đã bị chặn tạm thời do phát hiện hành vi đáng ngờ. Vui lòng thử lại sau ${delayTime}.`,
} as const;
