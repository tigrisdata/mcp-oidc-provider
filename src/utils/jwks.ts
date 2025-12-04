import * as crypto from 'node:crypto';

/**
 * JWK (JSON Web Key) type for signing keys.
 */
export interface JWK {
  kty: string;
  alg?: string;
  use?: string;
  kid?: string;
  [key: string]: unknown;
}

/**
 * JWKS (JSON Web Key Set) type.
 */
export interface JWKS {
  keys: JWK[];
}

/**
 * Options for generating JWKS.
 */
export interface GenerateJwksOptions {
  /**
   * Algorithm to use for key generation.
   * Default: 'RS256'
   */
  algorithm?: 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512';
}

/**
 * Generate a JSON Web Key Set (JWKS) for signing tokens.
 *
 * This utility helps you generate signing keys for production use.
 * Generate keys once and store them securely (e.g., in environment variables or a secrets manager).
 *
 * @param options - Key generation options
 * @returns A JWKS object containing the generated key(s)
 *
 * @example
 * ```typescript
 * import { generateJwks } from 'mcp-oidc-provider';
 *
 * // Generate keys and save to a file or environment variable
 * const jwks = await generateJwks();
 * console.log(JSON.stringify(jwks, null, 2));
 *
 * // Store the output securely and load it in production:
 * // JWKS={"keys":[...]}
 * const jwks = JSON.parse(process.env.JWKS);
 * ```
 */
export async function generateJwks(options?: GenerateJwksOptions): Promise<JWKS> {
  const algorithm = options?.algorithm ?? 'RS256';

  let jwk: JWK;
  const kid = crypto.randomBytes(16).toString('base64url');

  if (algorithm.startsWith('RS')) {
    // Generate RSA key pair
    const keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });

    const privateJwk = keyPair.privateKey.export({ format: 'jwk' }) as JWK;

    jwk = {
      ...privateJwk,
      alg: algorithm,
      use: 'sig',
      kid,
    };
  } else if (algorithm.startsWith('ES')) {
    // Map algorithm to curve (using OpenSSL curve names)
    const curveMap: Record<string, string> = {
      ES256: 'prime256v1',
      ES384: 'secp384r1',
      ES512: 'secp521r1',
    };
    const namedCurve = curveMap[algorithm];

    if (!namedCurve) {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }

    // Generate EC key pair
    const keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve,
    });

    const privateJwk = keyPair.privateKey.export({ format: 'jwk' }) as JWK;

    jwk = {
      ...privateJwk,
      alg: algorithm,
      use: 'sig',
      kid,
    };
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  return { keys: [jwk] };
}

/**
 * Generate development-only JWKS.
 * This creates keys deterministically for development use only.
 *
 * WARNING: Do not use these keys in production!
 *
 * @internal
 */
export function generateDevJwks(): JWKS {
  // Use a deterministic seed for development keys
  // This ensures the same keys are generated each run (for development convenience)
  const keyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

  const privateJwk = keyPair.privateKey.export({ format: 'jwk' }) as JWK;

  return {
    keys: [
      {
        ...privateJwk,
        alg: 'RS256',
        use: 'sig',
        kid: 'dev-key-1',
      },
    ],
  };
}
