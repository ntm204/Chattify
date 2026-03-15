import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  HttpStatus,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

export interface Response<T> {
  success: boolean;
  statusCode: number;
  message: string;
  data: T;
  timestamp: string;
}

import { Response as ExpressResponse } from 'express';

@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<
  T,
  Response<T>
> {
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<Response<T>> {
    const res = context.switchToHttp().getResponse<ExpressResponse>();
    const status = res.statusCode || HttpStatus.OK;

    return next.handle().pipe(
      map((payload: unknown) => {
        let message = 'Success';
        let data = payload as T;

        if (payload && typeof payload === 'object' && 'message' in payload) {
          const p = payload as Record<string, unknown>;
          message = (p.message as string) || 'Success';
          const { message: _, ...rest } = p;
          void _; // Mark as used
          data = (
            Object.keys(rest).length > 0
              ? rest.user && Object.keys(rest).length === 1
                ? rest.user
                : rest
              : null
          ) as T;
        }

        return {
          success: true,
          statusCode: status,
          message,
          data,
          timestamp: new Date().toISOString(),
        };
      }),
    );
  }
}
