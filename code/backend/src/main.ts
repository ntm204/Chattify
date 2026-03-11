import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Kích hoạt bộ HTTP Headers Security chống XSS, Clickjacking...
  app.use(helmet());

  // Kích hoạt đọc Cookie Security
  app.use(cookieParser());

  // Kích hoạt tính năng Validate tự động cho tất cả input
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Tự động loại bỏ các field không khai báo trong DTO
      forbidNonWhitelisted: true, // Báo lỗi nếu frontend gửi data thừa
      transform: true, // Tự động ép kiểu dữ liệu
    }),
  );

  // Bắt toàn bộ ngoại lệ và chuẩn hoá Format trả về cho Client
  app.useGlobalFilters(new AllExceptionsFilter());

  // Bật CORS cho phép Frontend gọi API (lấy từ env, mặc định localhost dev)
  // Khởi tạo ConfigService để đọc biến môi trường hợp lệ
  const configService = app.get(ConfigService);

  // Setup Swagger API Documentation
  const config = new DocumentBuilder()
    .setTitle('Chatiffy API')
    .setDescription(
      'The Enterprise Chatiffy Backend API Documentation. All Auth concepts are highly secured.',
    )
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const documentFactory = () => SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, documentFactory);

  // Bật CORS cho phép Frontend gọi API (lấy từ env, mặc định localhost dev)
  const corsOrigins = configService
    .get<string>('CORS_ORIGIN', 'http://localhost:3000,http://localhost:3001')
    .split(',')
    .map((o) => o.trim());
  app.enableCors({
    origin: corsOrigins,
    credentials: true,
  });

  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);
  console.log(`🚀 Application is running on: http://localhost:${port}`);
  console.log(
    `📚 Swagger Documentation available at: http://localhost:${port}/api/docs`,
  );
}
void bootstrap();
