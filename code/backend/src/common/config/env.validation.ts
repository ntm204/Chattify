import * as Joi from 'joi';

export const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  PORT: Joi.number().default(3000),

  // Database
  DATABASE_URL: Joi.string().required(),
  MONGODB_URI: Joi.string().required(),

  // Redis
  REDIS_URL: Joi.string().required(),

  // JWT Security
  JWT_SECRET: Joi.string().required(),
  JWT_2FA_SECRET: Joi.string().required(),

  // 2FA Encryption
  TWO_FACTOR_ENCRYPTION_KEY: Joi.string().required(),

  // Mail
  SMTP_HOST: Joi.string().optional(),
  SMTP_PORT: Joi.number().optional(),
  SMTP_USER: Joi.string().optional(),
  SMTP_PASS: Joi.string().optional(),

  // CORS
  CORS_ORIGIN: Joi.string().default(
    'http://localhost:3000,http://localhost:3001',
  ),
});
