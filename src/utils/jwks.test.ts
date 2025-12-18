import { describe, it, expect } from 'vitest';
import { generateJwks, generateDevJwks } from './jwks.js';

describe('jwks', () => {
  describe('generateJwks', () => {
    it('should generate RS256 keys by default', async () => {
      const jwks = await generateJwks();

      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0].alg).toBe('RS256');
      expect(jwks.keys[0].use).toBe('sig');
      expect(jwks.keys[0].kty).toBe('RSA');
      expect(jwks.keys[0].kid).toBeDefined();
    });

    it('should generate RS384 keys when specified', async () => {
      const jwks = await generateJwks({ algorithm: 'RS384' });

      expect(jwks.keys[0].alg).toBe('RS384');
      expect(jwks.keys[0].kty).toBe('RSA');
    });

    it('should generate RS512 keys when specified', async () => {
      const jwks = await generateJwks({ algorithm: 'RS512' });

      expect(jwks.keys[0].alg).toBe('RS512');
      expect(jwks.keys[0].kty).toBe('RSA');
    });

    it('should generate ES256 keys when specified', async () => {
      const jwks = await generateJwks({ algorithm: 'ES256' });

      expect(jwks.keys[0].alg).toBe('ES256');
      expect(jwks.keys[0].kty).toBe('EC');
      expect(jwks.keys[0].crv).toBe('P-256');
    });

    it('should generate ES384 keys when specified', async () => {
      const jwks = await generateJwks({ algorithm: 'ES384' });

      expect(jwks.keys[0].alg).toBe('ES384');
      expect(jwks.keys[0].kty).toBe('EC');
      expect(jwks.keys[0].crv).toBe('P-384');
    });

    it('should generate ES512 keys when specified', async () => {
      const jwks = await generateJwks({ algorithm: 'ES512' });

      expect(jwks.keys[0].alg).toBe('ES512');
      expect(jwks.keys[0].kty).toBe('EC');
      expect(jwks.keys[0].crv).toBe('P-521');
    });

    it('should generate unique kid for each call', async () => {
      const jwks1 = await generateJwks();
      const jwks2 = await generateJwks();

      expect(jwks1.keys[0].kid).not.toBe(jwks2.keys[0].kid);
    });

    it('should include private key components for RSA', async () => {
      const jwks = await generateJwks({ algorithm: 'RS256' });
      const key = jwks.keys[0];

      expect(key.n).toBeDefined();
      expect(key.e).toBeDefined();
      expect(key.d).toBeDefined();
      expect(key.p).toBeDefined();
      expect(key.q).toBeDefined();
    });

    it('should include private key components for EC', async () => {
      const jwks = await generateJwks({ algorithm: 'ES256' });
      const key = jwks.keys[0];

      expect(key.x).toBeDefined();
      expect(key.y).toBeDefined();
      expect(key.d).toBeDefined();
    });
  });

  describe('generateDevJwks', () => {
    it('should generate RS256 keys', () => {
      const jwks = generateDevJwks();

      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0].alg).toBe('RS256');
      expect(jwks.keys[0].use).toBe('sig');
      expect(jwks.keys[0].kty).toBe('RSA');
    });

    it('should use a consistent kid for dev keys', () => {
      const jwks = generateDevJwks();

      expect(jwks.keys[0].kid).toBe('dev-key-1');
    });
  });

  describe('error handling', () => {
    it('should throw error for unsupported EC algorithm', async () => {
      await expect(generateJwks({ algorithm: 'ES999' as 'ES256' })).rejects.toThrow(
        'Unsupported algorithm: ES999'
      );
    });

    it('should throw error for completely unsupported algorithm', async () => {
      await expect(generateJwks({ algorithm: 'HS256' as 'RS256' })).rejects.toThrow(
        'Unsupported algorithm: HS256'
      );
    });

    it('should throw error for invalid algorithm type', async () => {
      await expect(generateJwks({ algorithm: 'INVALID' as 'RS256' })).rejects.toThrow(
        'Unsupported algorithm: INVALID'
      );
    });
  });
});
