import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { generateOtpEmailTemplate } from './templates/otp-email.template';
import { generatePasswordResetTemplate } from './templates/password-reset.template';
import { AUTH_CONSTANTS } from '../config/auth.constants';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  private readonly logger = new Logger(MailService.name);

  constructor(private readonly configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('SMTP_HOST'),
      port: this.configService.get<number>('SMTP_PORT', 587),
      auth: {
        user: this.configService.get<string>('SMTP_USER'),
        pass: this.configService.get<string>('SMTP_PASS'),
      },
    });
  }

  async sendOtpEmail(to: string, otp: string) {
    const appName = AUTH_CONSTANTS.APP_NAME;
    const mailOptions = {
      from: `"${appName} Security" <no-reply@chatiffy.com>`,
      to,
      subject: `Mã Xác Thực ${appName} (OTP)`,
      html: generateOtpEmailTemplate(otp, appName),
    };

    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email đã gửi thành công tới ${to}`);
      if (this.configService.get<string>('NODE_ENV') !== 'production') {
        this.logger.debug(
          /* eslint-disable-next-line @typescript-eslint/no-unsafe-argument */
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
    const appName = AUTH_CONSTANTS.APP_NAME;
    const mailOptions = {
      from: `"${appName} Security" <no-reply@chatiffy.com>`,
      to,
      subject: `Lấy lại mật khẩu ${appName}`,
      html: generatePasswordResetTemplate(otp, appName),
    };

    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email quên mật khẩu đã gửi thành công tới ${to}`);
      if (this.configService.get<string>('NODE_ENV') !== 'production') {
        this.logger.debug(
          /* eslint-disable-next-line @typescript-eslint/no-unsafe-argument */
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
