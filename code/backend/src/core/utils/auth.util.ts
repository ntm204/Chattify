import { parsePhoneNumberFromString, CountryCode } from 'libphonenumber-js';
import * as argon2 from 'argon2';
import { createHash } from 'crypto';
import { AUTH_CONSTANTS } from '../config/auth.constants';

/**
 * Utility class for Authentication and Identifier handling
 */
export class AuthUtils {
  static async hashPassword(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
    });
  }

  static async verifyPassword(
    hash: string,
    plainTextPassword: string,
  ): Promise<boolean> {
    try {
      return await argon2.verify(hash, plainTextPassword);
    } catch {
      return false;
    }
  }

  static async applyTimingDelay(): Promise<void> {
    await new Promise((resolve) =>
      setTimeout(resolve, AUTH_CONSTANTS.TIMING_DELAY_MS),
    );
  }

  static async verifyPasswordOrDelay(
    hash: string | null | undefined,
    plainTextPassword: string,
  ): Promise<boolean> {
    if (!hash) {
      await this.applyTimingDelay();
      return false;
    }

    return this.verifyPassword(hash, plainTextPassword);
  }

  /**
   * Checks if a password has been leaked in data breaches using HaveIBeenPwned API.
   * Uses K-Anonymity (only sends first 5 chars of SHA-1 hash).
   */
  static async isPasswordPwned(password: string): Promise<boolean> {
    try {
      const sha1Hash = createHash('sha1')
        .update(password)
        .digest('hex')
        .toUpperCase();
      const prefix = sha1Hash.slice(0, 5);
      const suffix = sha1Hash.slice(5);

      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        AUTH_CONSTANTS.HIBP_TIMEOUT_MS,
      );

      try {
        const response = await fetch(
          `https://api.pwnedpasswords.com/range/${prefix}`,
          { signal: controller.signal },
        );
        clearTimeout(timeoutId);

        if (!response.ok) return false;

        const body = await response.text();
        const lines = body.split('\n');

        return lines.some((line) => {
          const [hashSuffix] = line.split(':');
          return hashSuffix.trim() === suffix;
        });
      } finally {
        clearTimeout(timeoutId);
      }
    } catch {
      // If API is down or timeout, we don't block the user (Fail-open for UX)
      return false;
    }
  }

  /**
   * Normalize an identifier (Email or Phone)
   * If it's an email: lowercase and trim
   * If it's a phone: format to E.164 standard (+84...)
   */
  static normalizeIdentifier(
    identifier: string,
    region: CountryCode = 'VN',
  ): string {
    const trimmed = identifier.trim();

    // Check if it's potentially an email
    if (trimmed.includes('@')) {
      return trimmed.toLowerCase();
    }

    // Try to parse as phone number
    const phoneNumber = parsePhoneNumberFromString(trimmed, region);
    if (phoneNumber && phoneNumber.isValid()) {
      return phoneNumber.format('E.164');
    }

    // If neither, return trimmed (fallback)
    return trimmed;
  }

  /**
   * Check if the identifier is a valid phone number
   */
  static isPhoneNumber(
    identifier: string,
    region: CountryCode = 'VN',
  ): boolean {
    const phoneNumber = parsePhoneNumberFromString(identifier, region);
    return !!(phoneNumber && phoneNumber.isValid());
  }

  /**
   * Check if the identifier is a valid email
   */
  static isEmail(identifier: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(identifier);
  }

  /**
   * Determine the type of identifier
   */
  static getIdentifierType(identifier: string): 'PHONE' | 'EMAIL' | 'UNKNOWN' {
    if (this.isEmail(identifier)) return 'EMAIL';
    if (this.isPhoneNumber(identifier)) return 'PHONE';
    return 'UNKNOWN';
  }
}
