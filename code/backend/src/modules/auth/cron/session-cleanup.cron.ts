import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { PrismaService } from '../../../core/prisma/prisma.service';

@Injectable()
export class SessionCleanupCron {
  private readonly logger = new Logger(SessionCleanupCron.name);

  constructor(private readonly prisma: PrismaService) {}

  @Cron('0 3 * * *') // Run every day at 3 AM
  async cleanupExpiredSessions() {
    this.logger.log('Starting scheduled cleanup of expired sessions...');
    try {
      const result = await this.prisma.userSession.deleteMany({
        where: {
          expiresAt: {
            lt: new Date(),
          },
        },
      });
      this.logger.log(
        `Successfully cleaned up ${result.count} expired sessions.`,
      );
    } catch (error) {
      this.logger.error('Failed to cleanup expired sessions', error);
    }
  }
}
