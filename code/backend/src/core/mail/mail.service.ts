import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  private readonly logger = new Logger(MailService.name);

  constructor(private readonly configService: ConfigService) {
    // Để setup thực tế, bạn sẽ cần thay thế bằng thông số SMTP của dự án (AWS SES, SendGrid, Gmail)
    // Tại đây tôi dùng Ethereal (máy chủ test mail giả lập) cho mục đích Dev
    // Nếu có biến môi trường SMTP, sẽ dùng biến môi trường.
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('SMTP_HOST', 'smtp.ethereal.email'),
      port: this.configService.get<number>('SMTP_PORT', 587),
      auth: {
        user: this.configService.get<string>(
          'SMTP_USER',
          'bd57v2lrw5enq756@ethereal.email',
        ),
        pass: this.configService.get<string>('SMTP_PASS', 'yVJvUWQ79b7GNv8X6Y'),
      },
    });
  }

  async sendOtpEmail(to: string, otp: string) {
    const mailOptions = {
      from: '"Chatiffy Security" <no-reply@chatiffy.com>',
      to,
      subject: 'Mã Xác Thực Chatiffy (OTP)',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
          <div style="background-color: #4F46E5; padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">Khởi tạo Tài Khoản Chatiffy</h1>
          </div>
          <div style="padding: 30px; background-color: #f9fafb;">
            <p style="font-size: 16px; color: #333;">Xin chào bạn,</p>
            <p style="font-size: 16px; color: #333;">Bạn vừa yêu cầu mã xác thực cho tài khoản Chatiffy. Vui lòng sử dụng mã thiết lập mật khẩu một lần (OTP) dưới đây:</p>
            
            <div style="text-align: center; margin: 30px 0;">
              <span style="display: inline-block; font-size: 28px; font-weight: bold; letter-spacing: 4px; padding: 10px 20px; background-color: #e5e7eb; border-radius: 8px; color: #111827;">
                ${otp}
              </span>
            </div>
            
            <p style="font-size: 14px; color: #666; margin-top: 20px;">Mã này chỉ có hiệu lực trong vòng 5 phút.</p>
            <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;" />
            <p style="font-size: 12px; color: #9ca3af; text-align: center;">Nếu bạn không yêu cầu mã này, xin bỏ qua email. Hệ thống sẽ tự hủy nó.</p>
          </div>
        </div>
      `,
    };

    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email đã gửi thành công tới ${to}`);
      if (this.configService.get<string>('NODE_ENV') !== 'production') {
        // Trong Ethereal test, ta có thể xem ngay link email
        this.logger.debug(
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
          `[TEST] Preview URL: ${nodemailer.getTestMessageUrl(info)}`,
        );
      }
    } catch (error) {
      this.logger.error(`Lỗi gửi email cho ${to}:`, error);
      throw new Error(
        'Lỗi gửi email. Hệ thống đang gặp sự cố kết nối tới máy chủ gửi mail.',
      );
    }
  }

  async sendPasswordResetOtpEmail(to: string, otp: string) {
    const mailOptions = {
      from: '"Chatiffy Security" <no-reply@chatiffy.com>',
      to,
      subject: 'Lấy lại mật khẩu Chatiffy',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
          <div style="background-color: #EF4444; padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">Khôi phục Mật khẩu Chatiffy</h1>
          </div>
          <div style="padding: 30px; background-color: #f9fafb;">
            <p style="font-size: 16px; color: #333;">Xin chào bạn,</p>
            <p style="font-size: 16px; color: #333;">Ai đó (hy vọng là bạn) vừa yêu cầu đặt lại mật khẩu của bạn. Vui lòng sử dụng mã OTP dưới đây để xác nhận:</p>
            
            <div style="text-align: center; margin: 30px 0;">
              <span style="display: inline-block; font-size: 28px; font-weight: bold; letter-spacing: 4px; padding: 10px 20px; background-color: #e5e7eb; border-radius: 8px; color: #111827;">
                ${otp}
              </span>
            </div>
            
            <p style="font-size: 14px; color: #666; margin-top: 20px;">Mã này chỉ có hiệu lực trong vòng 5 phút. Vui lòng không chia sẻ mã này cho bất kỳ ai.</p>
          </div>
        </div>
      `,
    };

    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email quên mật khẩu đã gửi thành công tới ${to}`);
      if (this.configService.get<string>('NODE_ENV') !== 'production') {
        this.logger.debug(
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
          `[TEST] Preview URL: ${nodemailer.getTestMessageUrl(info)}`,
        );
      }
    } catch (error) {
      this.logger.error(`Lỗi gửi email quên mật khẩu cho ${to}:`, error);
      throw new Error(
        'Lỗi gửi email. Hệ thống đang gặp sự cố kết nối tới máy chủ gửi mail.',
      );
    }
  }
}
