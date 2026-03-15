import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { RedisService } from '../../../core/redis/redis.service';

@Injectable()
export class SessionCleanupCron {
  private readonly logger = new Logger(SessionCleanupCron.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService,
  ) {}

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async cleanupExpiredSessions() {
    this.logger.log('Bắt đầu dọn dẹp session hết hạn...');
    try {
      const now = new Date();
      // Lấy danh sách sessions sắp bị xóa để xóa trên Redis (nếu cần)
      const expiredSessions = await this.prisma.userSession.findMany({
        where: { expiresAt: { lt: now } },
        select: { id: true, userId: true },
      });

      if (expiredSessions.length > 0) {
        const result = await this.prisma.userSession.deleteMany({
          where: { expiresAt: { lt: now } },
        });

        // Cleanup Redis using pipeline for batch performance
        const redisClient = this.redisService.getClient();
        const pipeline = redisClient.pipeline();
        for (const session of expiredSessions) {
          pipeline.del(`session:${session.id}`);
          pipeline.srem(`user_sessions:${session.userId}`, session.id);
        }
        await pipeline.exec();

        this.logger.log(
          `Đã xóa ${result.count} session hết hạn từ DB & Redis.`,
        );
      } else {
        this.logger.log('Không có session nào cần xóa.');
      }
    } catch (error) {
      this.logger.error('Lỗi khi dọn dẹp session:', error);
    }
  }

  // Chạy lúc 1h sáng Chủ nhật hàng tuần
  @Cron('0 1 * * 0')
  async cleanupOldAuthLogs() {
    this.logger.log('Bắt đầu dọn dẹp AuthLog cũ (hơn 90 ngày)...');
    try {
      const ninetyDaysAgo = new Date();
      ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);

      const result = await this.prisma.authLog.deleteMany({
        where: { createdAt: { lt: ninetyDaysAgo } },
      });

      this.logger.log(`Đã xóa ${result.count} bản ghi AuthLog cũ.`);
    } catch (error) {
      this.logger.error('Lỗi khi dọn dẹp AuthLog:', error);
    }
  }
}
