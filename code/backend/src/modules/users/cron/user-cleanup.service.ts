import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../../../core/prisma/prisma.service';

@Injectable()
export class UserCleanupService {
  private readonly logger = new Logger(UserCleanupService.name);

  constructor(private readonly prisma: PrismaService) {}

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async cleanupUnverifiedUsers() {
    this.logger.log('Starting cleanup of unverified users...');

    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    try {
      const result = await this.prisma.user.deleteMany({
        where: {
          isVerified: false,
          createdAt: {
            lt: twentyFourHoursAgo,
          },
        },
      });

      this.logger.log(
        `Cleanup completed. Deleted ${result.count} unverified users.`,
      );
    } catch (error) {
      this.logger.error(
        'Failed to cleanup unverified users',
        error instanceof Error ? error.stack : String(error),
      );
    }
  }
}
