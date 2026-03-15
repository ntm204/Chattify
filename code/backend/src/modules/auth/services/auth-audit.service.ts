import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../../core/prisma/prisma.service';
import { getLocationFromIp } from '../../../core/utils/geo.util';
import {
  AuthEventAction,
  AuthEventStatus,
} from '../constants/auth-events.constants';

interface AuthAuditInput {
  userId?: string;
  action: AuthEventAction;
  status: AuthEventStatus;
  ipAddress?: string;
  deviceInfo?: string;
  location?: string | null;
  failureReason?: string;
}

@Injectable()
export class AuthAuditService {
  constructor(private readonly prisma: PrismaService) {}

  async log(input: AuthAuditInput, tx?: Prisma.TransactionClient) {
    const client = tx ?? this.prisma;
    const location = input.location ?? getLocationFromIp(input.ipAddress);

    await client.authLog.create({
      data: {
        userId: input.userId ?? null,
        action: input.action,
        status: input.status,
        ipAddress: input.ipAddress,
        deviceInfo: input.deviceInfo,
        location,
        failureReason: input.failureReason,
      },
    });
  }

  /**
   * Checks if the device has been used for successful login before.
   */
  async isNewDevice(userId: string, deviceInfo?: string): Promise<boolean> {
    if (!deviceInfo) return false;

    const previousLogs = await this.prisma.authLog.findFirst({
      where: {
        userId,
        deviceInfo,
        status: 'SUCCESS', // Using string since AuthEventStatus is a string type
      },
    });

    return !previousLogs;
  }
}
