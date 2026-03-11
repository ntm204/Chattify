/**
 * Authentication Constants
 * Centralized security configurations for the Chatiffy auth module.
 */

export const AUTH_CONSTANTS = {
  // ===== Account Lockout =====
  MAX_LOGIN_ATTEMPTS: 10,
  LOCKOUT_WARNING_THRESHOLD: 3,
  LOCKOUT_DURATION_SECONDS: 900, // 15 minutes

  // ===== IP-level Rate Limiting =====
  MAX_IP_ATTEMPTS: 50,
  IP_LOCKOUT_DURATION_SECONDS: 900, // 15 minutes

  // ===== Password =====
  SALT_ROUNDS: 10,

  // ===== Session & Token =====
  ACCESS_TOKEN_EXPIRY: '15m',
  SESSION_EXPIRY_MS: 7 * 24 * 60 * 60 * 1000,
  SESSION_EXPIRY_SECONDS: 7 * 24 * 60 * 60,
  MAX_SESSIONS_PER_USER: 5,

  // ===== Cookie =====
  COOKIE_ACCESS_TOKEN_MAX_AGE: 15 * 60 * 1000,
  COOKIE_REFRESH_TOKEN_MAX_AGE: 7 * 24 * 60 * 60 * 1000,

  // ===== OTP =====
  OTP_TTL_SECONDS: 300,
  OTP_COOLDOWN_SECONDS: 60,
  OTP_DAILY_LIMIT: 10,
  OTP_MAX_ATTEMPTS: 5,

  // ===== 2FA =====
  TWO_FA_MAX_ATTEMPTS: 5,
  TWO_FA_LOCKOUT_SECONDS: 300,
  TWO_FA_TEMP_TOKEN_EXPIRY: '5m',

  // ===== Timing Attack Protection =====
  TIMING_DELAY_MS: 600,
} as const;
