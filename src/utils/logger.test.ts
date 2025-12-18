import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createConsoleLogger, noopLogger } from './logger.js';

describe('logger', () => {
  let consoleSpy: {
    debug: ReturnType<typeof vi.spyOn>;
    info: ReturnType<typeof vi.spyOn>;
    warn: ReturnType<typeof vi.spyOn>;
    error: ReturnType<typeof vi.spyOn>;
  };

  beforeEach(() => {
    consoleSpy = {
      debug: vi.spyOn(console, 'debug').mockImplementation(() => {}),
      info: vi.spyOn(console, 'info').mockImplementation(() => {}),
      warn: vi.spyOn(console, 'warn').mockImplementation(() => {}),
      error: vi.spyOn(console, 'error').mockImplementation(() => {}),
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('createConsoleLogger', () => {
    it('should create a logger with default info level', () => {
      const logger = createConsoleLogger();

      logger.info('test message');
      expect(consoleSpy.info).toHaveBeenCalledWith('[INFO] test message');
    });

    it('should not log debug messages at info level', () => {
      const logger = createConsoleLogger('info');

      logger.debug('debug message');
      expect(consoleSpy.debug).not.toHaveBeenCalled();
    });

    it('should log debug messages at debug level', () => {
      const logger = createConsoleLogger('debug');

      logger.debug('debug message');
      expect(consoleSpy.debug).toHaveBeenCalledWith('[DEBUG] debug message');
    });

    it('should log warn messages at warn level', () => {
      const logger = createConsoleLogger('warn');

      logger.warn('warn message');
      expect(consoleSpy.warn).toHaveBeenCalledWith('[WARN] warn message');
    });

    it('should not log info messages at warn level', () => {
      const logger = createConsoleLogger('warn');

      logger.info('info message');
      expect(consoleSpy.info).not.toHaveBeenCalled();
    });

    it('should log error messages at error level', () => {
      const logger = createConsoleLogger('error');

      logger.error('error message');
      expect(consoleSpy.error).toHaveBeenCalledWith('[ERROR] error message');
    });

    it('should not log warn messages at error level', () => {
      const logger = createConsoleLogger('error');

      logger.warn('warn message');
      expect(consoleSpy.warn).not.toHaveBeenCalled();
    });

    it('should include meta data in log messages', () => {
      const logger = createConsoleLogger('debug');

      logger.debug('message', { key: 'value' });
      expect(consoleSpy.debug).toHaveBeenCalledWith('[DEBUG] message {"key":"value"}');
    });

    it('should handle meta in info logs', () => {
      const logger = createConsoleLogger('info');

      logger.info('message', { foo: 'bar' });
      expect(consoleSpy.info).toHaveBeenCalledWith('[INFO] message {"foo":"bar"}');
    });

    it('should handle meta in warn logs', () => {
      const logger = createConsoleLogger('warn');

      logger.warn('message', { foo: 'bar' });
      expect(consoleSpy.warn).toHaveBeenCalledWith('[WARN] message {"foo":"bar"}');
    });

    it('should handle meta in error logs', () => {
      const logger = createConsoleLogger('error');

      logger.error('message', { error: 'details' });
      expect(consoleSpy.error).toHaveBeenCalledWith('[ERROR] message {"error":"details"}');
    });

    it('should handle undefined meta', () => {
      const logger = createConsoleLogger('info');

      logger.info('message', undefined);
      expect(consoleSpy.info).toHaveBeenCalledWith('[INFO] message');
    });

    it('should handle circular references in meta', () => {
      const logger = createConsoleLogger('info');
      const circular: Record<string, unknown> = { a: 1 };
      circular['self'] = circular;

      logger.info('message', circular);
      expect(consoleSpy.info).toHaveBeenCalledWith('[INFO] message [unserializable]');
    });

    it('should log all levels at debug', () => {
      const logger = createConsoleLogger('debug');

      logger.debug('d');
      logger.info('i');
      logger.warn('w');
      logger.error('e');

      expect(consoleSpy.debug).toHaveBeenCalled();
      expect(consoleSpy.info).toHaveBeenCalled();
      expect(consoleSpy.warn).toHaveBeenCalled();
      expect(consoleSpy.error).toHaveBeenCalled();
    });

    it('should only log error at error level', () => {
      const logger = createConsoleLogger('error');

      logger.debug('d');
      logger.info('i');
      logger.warn('w');
      logger.error('e');

      expect(consoleSpy.debug).not.toHaveBeenCalled();
      expect(consoleSpy.info).not.toHaveBeenCalled();
      expect(consoleSpy.warn).not.toHaveBeenCalled();
      expect(consoleSpy.error).toHaveBeenCalled();
    });
  });

  describe('noopLogger', () => {
    it('should have all logger methods', () => {
      expect(noopLogger.debug).toBeDefined();
      expect(noopLogger.info).toBeDefined();
      expect(noopLogger.warn).toBeDefined();
      expect(noopLogger.error).toBeDefined();
    });

    it('should not output anything', () => {
      noopLogger.debug('debug');
      noopLogger.info('info');
      noopLogger.warn('warn');
      noopLogger.error('error');

      expect(consoleSpy.debug).not.toHaveBeenCalled();
      expect(consoleSpy.info).not.toHaveBeenCalled();
      expect(consoleSpy.warn).not.toHaveBeenCalled();
      expect(consoleSpy.error).not.toHaveBeenCalled();
    });

    it('should accept meta without error', () => {
      expect(() => noopLogger.debug('msg', { key: 'value' })).not.toThrow();
      expect(() => noopLogger.info('msg', { key: 'value' })).not.toThrow();
      expect(() => noopLogger.warn('msg', { key: 'value' })).not.toThrow();
      expect(() => noopLogger.error('msg', { key: 'value' })).not.toThrow();
    });
  });
});
