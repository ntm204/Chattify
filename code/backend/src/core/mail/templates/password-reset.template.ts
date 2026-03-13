import { AUTH_CONSTANTS } from '../../config/auth.constants';

export const generatePasswordResetTemplate = (
  otp: string,
  appName: string = AUTH_CONSTANTS.APP_NAME,
) => `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
  <div style="background-color: #EF4444; padding: 20px; text-align: center;">
    <h1 style="color: white; margin: 0;">Khôi phục Mật khẩu ${appName}</h1>
  </div>
  <div style="padding: 30px; background-color: #f9fafb;">
    <p style="font-size: 16px; color: #333;">Xin chào bạn,</p>
    <p style="font-size: 16px; color: #333;">Ai đó (hy vọng là bạn) vừa yêu cầu đặt lại mật khẩu của bạn. Vui lòng sử dụng mã OTP dưới đây để xác nhận:</p>

    <div style="text-align: center; margin: 30px 0;">
      <span style="display: inline-block; font-size: 28px; font-weight: bold; letter-spacing: 4px; padding: 10px 20px; background-color: #e5e7eb; border-radius: 8px; color: #111827;">
        ${otp}
      </span>
    </div>

    <p style="font-size: 14px; color: #666; margin-top: 20px;">Mã này chỉ có hiệu lực trong vòng ${
      AUTH_CONSTANTS.OTP_TTL_SECONDS / 60
    } phút. Vui lòng không chia sẻ mã này cho bất kỳ ai.</p>
  </div>
</div>
`;
