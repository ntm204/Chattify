import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Lỗi máy chủ nội bộ. Vui lòng thử lại sau.';
    let details = null;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse() as Record<
        string,
        unknown
      >;

      // Nếu lỗi từ class-validator (Bad Request), exceptionResponse.message sẽ là mảng các chi tiết lỗi
      if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
        message = (exceptionResponse.error as string) || exception.message;

        // Trích xuất chi tiết nếu có
        if (Array.isArray(exceptionResponse.message)) {
          details = exceptionResponse.message;
          message = 'Dữ liệu đầu vào không hợp lệ';
        } else if (typeof exceptionResponse.message === 'string') {
          message = exceptionResponse.message;
        }
      } else {
        message = exception.message;
      }
    } else {
      // Lỗi ngoài ý muốn (Database crash, TypeError...)
      this.logger.error(
        `[UNHANDLED EXCEPTION] ${request.method} ${request.url}`,
        exception instanceof Error
          ? exception.stack
          : JSON.stringify(exception),
      );
    }

    // Cấu trúc Response chuẩn hoá của hệ thống
    const errorResponseBody: {
      success: boolean;
      statusCode: number;
      path: string;
      timestamp: string;
      message: string;
      details?: unknown;
    } = {
      success: false,
      statusCode: status,
      path: request.url,
      timestamp: new Date().toISOString(),
      message,
    };

    if (details) {
      errorResponseBody.details = details;
    }

    response.status(status).json(errorResponseBody);
  }
}
