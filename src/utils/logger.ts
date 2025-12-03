/**
 * Log levels supported by the logger.
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Logger interface for the OIDC provider.
 * Implement this interface to use a custom logger.
 */
export interface Logger {
  debug(message: string, meta?: Record<string, unknown>): void;
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: unknown): void;
}

/**
 * Create a console logger with optional log level filtering.
 *
 * @param minLevel - Minimum log level to output (default: 'info')
 * @returns A Logger instance
 */
export function createConsoleLogger(minLevel: LogLevel = 'info'): Logger {
  const levels: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  };

  const shouldLog = (level: LogLevel): boolean => {
    return levels[level] >= levels[minLevel];
  };

  const formatMeta = (meta?: Record<string, unknown> | unknown): string => {
    if (!meta) return '';
    try {
      return ' ' + JSON.stringify(meta);
    } catch {
      return ' [unserializable]';
    }
  };

  return {
    debug(message: string, meta?: Record<string, unknown>): void {
      if (shouldLog('debug')) {
        console.debug(`[DEBUG] ${message}${formatMeta(meta)}`);
      }
    },
    info(message: string, meta?: Record<string, unknown>): void {
      if (shouldLog('info')) {
        console.info(`[INFO] ${message}${formatMeta(meta)}`);
      }
    },
    warn(message: string, meta?: Record<string, unknown>): void {
      if (shouldLog('warn')) {
        console.warn(`[WARN] ${message}${formatMeta(meta)}`);
      }
    },
    error(message: string, meta?: unknown): void {
      if (shouldLog('error')) {
        console.error(`[ERROR] ${message}${formatMeta(meta as Record<string, unknown>)}`);
      }
    },
  };
}

/**
 * No-op logger that discards all log messages.
 * Useful for testing or when logging is not desired.
 */
export const noopLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};
