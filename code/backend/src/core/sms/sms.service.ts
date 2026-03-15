import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Twilio } from 'twilio';
import { LogUtils } from '../utils/log.util';

@Injectable()
export class SmsService {
  private readonly logger = new Logger(SmsService.name);
  private readonly twilioClient: Twilio | null = null;
  private readonly isProd: boolean;

  constructor(private readonly configService: ConfigService) {
    this.isProd = this.configService.get<string>('NODE_ENV') === 'production';

    const accountSid = this.configService.get<string>('TWILIO_ACCOUNT_SID');
    const authToken = this.configService.get<string>('TWILIO_AUTH_TOKEN');

    if (this.isProd && accountSid && authToken) {
      this.twilioClient = new Twilio(accountSid, authToken);
    }
  }

  /**
   * Send SMS to a phone number
   */
  async sendSms(to: string, message: string): Promise<boolean> {
    const from =
      this.configService.get<string>('TWILIO_PHONE_NUMBER') || 'Chatiffy';

    try {
      if (this.twilioClient && this.isProd) {
        await this.twilioClient.messages.create({
          body: message,
          from,
          to,
        });
        this.logger.log(
          `SMS sent successfully to ${LogUtils.maskIdentifier(to)} (via Twilio)`,
        );
      } else {
        // Dev/Mock Mode — only log OTP content in development
        this.logger.warn('--- SMS MOCK MODE ---');
        this.logger.warn(`To: ${LogUtils.maskIdentifier(to)}`);
        if (this.configService.get<string>('NODE_ENV') === 'development') {
          this.logger.warn(`Message: ${message}`);
        } else {
          this.logger.warn(
            'Message: [REDACTED — set NODE_ENV=development to view]',
          );
        }
        this.logger.warn('---------------------');
      }
      return true;
    } catch (error) {
      this.logger.error(
        `Failed to send SMS to ${to}`,
        error instanceof Error ? error.stack : String(error),
      );
      return false;
    }
  }

  /**
   * Send OTP specifically
   */
  async sendOtp(to: string, otp: string): Promise<boolean> {
    const message = `[Chatiffy] Ma xac thuc cua ban la: ${otp}. Ma co hieu luc trong 5 phut. Khong chia se ma nay voi bat ky ai.`;
    return this.sendSms(to, message);
  }
}
