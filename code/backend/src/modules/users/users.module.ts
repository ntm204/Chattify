import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UserCleanupService } from './cron/user-cleanup.service';
import { UsersController } from './users.controller';

@Module({
  controllers: [UsersController],
  providers: [UsersService, UserCleanupService],
  exports: [UsersService], // Export ra để AuthModule sử dụng
})
export class UsersModule {}
