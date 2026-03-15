import {
  Injectable,
  Logger,
  OnModuleInit,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { generateOtpEmailTemplate } from './templates/otp-email.template';
import { generatePasswordResetTemplate } from './templates/password-reset.template';
import { AUTH_CONSTANTS } from '../config/auth.constants';

@Injectable()
export class MailService implements OnModuleInit {
  private transporter: nodemailer.Transporter | null = null;
  private readonly logger = new Logger(MailService.name);

  constructor(private readonly configService: ConfigService) {}

  async onModuleInit() {
    await this.setupTransporter();
  }

  private async setupTransporter() {
    const host = this.configService.get<string>('SMTP_HOST');
    const user = this.configService.get<string>('SMTP_USER');
    const pass = this.configService.get<string>('SMTP_PASS');

    if (host && user && pass) {
      this.transporter = nodemailer.createTransport({
        host,
        port: this.configService.get<number>('SMTP_PORT', 587),
        secure: this.configService.get<number>('SMTP_PORT') === 465,
        auth: { user, pass },
        connectionTimeout: 5000,
      });

      try {
        await this.transporter.verify();
        this.logger.log('SMTP Transporter verified using .env credentials.');
        return;
      } catch {
        this.logger.warn(
          'SMTP .env credentials failed. Attempting to create Ethereal account...',
        );
      }
    }

    // Nếu config .env lỗi hoặc thiếu, tự tạo tài khoản test Ethereal (Auto-fallback)
    if (this.configService.get<string>('NODE_ENV') !== 'production') {
      try {
        const testAccount = await nodemailer.createTestAccount();
        this.transporter = nodemailer.createTransport({
          host: 'smtp.ethereal.email',
          port: 587,
          secure: false,
          auth: { user: testAccount.user, pass: testAccount.pass },
        });
        this.logger.log('✅ Created temporary Ethereal account for testing.');
      } catch {
        this.logger.error(
          'Failed to create Ethereal account. Email will not work.',
        );
      }
    }
  }

  private async send(options: nodemailer.SendMailOptions): Promise<void> {
    if (!this.transporter) {
      this.logger.error('MailService: No transporter available!');
      return;
    }

    try {
      /* eslint-disable @typescript-eslint/no-unsafe-assignment */
      const info = await this.transporter.sendMail(options);

      const to = options.to as any;

      const recipient = Array.isArray(to) ? to.join(',') : String(to || '');
      this.logger.log(`Email sent to ${recipient}`);

      /* eslint-disable @typescript-eslint/no-unsafe-argument */
      const previewUrl = nodemailer.getTestMessageUrl(info);
      if (previewUrl) {
        // LUÔN IN RA CONSOLE ĐỂ NGƯỜI DÙNG THẤY TRONG MÔI TRƯỜNG DEV
        console.log('\n----------------------------------------------');
        console.log('🔗 MAIL PREVIEW URL:', previewUrl);
        console.log('----------------------------------------------\n');
      }
      /* eslint-enable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument */
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error(`Failed to send email: ${msg}`);
      if (this.configService.get<string>('NODE_ENV') === 'production') {
        throw new InternalServerErrorException('Lỗi hệ thống gửi thư điện tử.');
      }
    }
  }

  async sendOtpEmail(to: string, otp: string): Promise<void> {
    const appName = AUTH_CONSTANTS.APP_NAME;
    await this.send({
      from: `"${appName} Security" <no-reply@chatiffy.com>`,
      to,
      subject: `Mã Xác Thực ${appName} (OTP)`,
      html: generateOtpEmailTemplate(otp, appName),
    });
  }

  async sendPasswordResetOtpEmail(to: string, otp: string): Promise<void> {
    const appName = AUTH_CONSTANTS.APP_NAME;
    await this.send({
      from: `"${appName} Security" <no-reply@chatiffy.com>`,
      to,
      subject: `Lấy lại mật khẩu ${appName}`,
      html: generatePasswordResetTemplate(otp, appName),
    });
  }

  async sendSecurityAlertEmail(
    to: string,
    action: string,
    details: { ip: string; location: string; device: string },
  ): Promise<void> {
    const appName = AUTH_CONSTANTS.APP_NAME;
    await this.send({
      from: `"${appName} Security" <security@chatiffy.com>`,
      to,
      subject: `[Cảnh báo bảo mật] ${action} - ${appName}`,
      html: `
        <div style="font-family: sans-serif; padding: 20px;">
          <h2>Thông báo bảo mật từ ${appName}</h2>
          <p>Chào bạn,</p>
          <p>Chúng tôi phát hiện hành động sau trên tài khoản của bạn:</p>
          <p><b>Hạnh động:</b> ${action}</p>
          <p><b>Thời gian:</b> ${new Date().toLocaleString('vi-VN')}</p>
          <p><b>Địa chỉ IP:</b> ${details.ip}</p>
          <p><b>Vị trí:</b> ${details.location}</p>
          <p><b>Thiết bị:</b> ${details.device}</p>
          <p style="margin-top: 20px; color: #555;">Nếu đây là hành động của bạn, bạn có thể bỏ qua email này.</p>
          <p style="color: #d93025; font-weight: bold;">Nếu bạn KHÔNG thực hiện hành động này, vui lòng đổi mật khẩu ngay lập tức và liên hệ bộ phận hỗ trợ.</p>
          <hr />
          <p style="font-size: 12px; color: #888;">Đây là email tự động, vui lòng không phản hồi.</p>
        </div>
      `,
    });
  }
}
