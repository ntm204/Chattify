import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly redisClient: Redis;

  constructor(private readonly configService: ConfigService) {
    this.redisClient = new Redis(
      this.configService.get<string>('REDIS_URL', 'redis://localhost:6379'),
    );
  }

  onModuleInit() {
    console.log('Redis connected successfully!');
  }

  onModuleDestroy() {
    void this.redisClient.quit();
  }

  getClient(): Redis {
    return this.redisClient;
  }

  async setCache(
    key: string,
    value: string,
    ttlSeconds?: number,
  ): Promise<void> {
    if (ttlSeconds) {
      await this.redisClient.set(key, value, 'EX', ttlSeconds);
    } else {
      await this.redisClient.set(key, value);
    }
  }

  async getCache(key: string): Promise<string | null> {
    return this.redisClient.get(key);
  }

  async deleteCache(key: string): Promise<void> {
    await this.redisClient.del(key);
  }
}
