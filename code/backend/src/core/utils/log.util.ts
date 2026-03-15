/**
 * Logging Utility
 * Provides PII masking for identifiers (email, phone) in log output.
 */
export class LogUtils {
  /**
   * Mask an identifier for safe logging.
   * - Email: "nguy***@gmail.com"
   * - Phone: "+849***5678"
   * - Fallback: "***"
   */
  static maskIdentifier(identifier: string): string {
    if (!identifier) return '***';

    const trimmed = identifier.trim();

    // Email masking
    if (trimmed.includes('@')) {
      const [local, domain] = trimmed.split('@');
      if (local.length <= 2) {
        return `${local[0]}***@${domain}`;
      }
      return `${local.substring(0, 4)}***@${domain}`;
    }

    // Phone masking (E.164 format: +84912345678)
    if (trimmed.startsWith('+') && trimmed.length >= 8) {
      const prefix = trimmed.substring(0, 4);
      const suffix = trimmed.substring(trimmed.length - 4);
      return `${prefix}***${suffix}`;
    }

    // Fallback: mask middle portion
    if (trimmed.length <= 4) return '***';
    return `${trimmed.substring(0, 2)}***${trimmed.substring(trimmed.length - 2)}`;
  }
}
