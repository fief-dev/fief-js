/**
 * Interface that should follow a class to implement a crypto helper.
 *
 * It's useful because we have different implementations in browser and NodeJS.
 */
export interface ICryptoHelper {
  /**
   * Return the validation hash of a value.
   *
   * Useful to check the validity `c_hash` and `at_hash` claims.
   *
   * @param value - The value to hash.
   *
   * @returns The hashed value.
   */
  getValidationHash: (value: string) => Promise<string>;

  /**
   * Check if a hash corresponds to the provided value.
   *
   * Useful to check the validity `c_hash` and `at_hash` claims.
   *
   * @param value - The plain value to challenge.
   * @param hash - The hash to compare with.
   *
   * @returns If the hash is valid.
   */
  isValidHash: (value: string, hash: string) => Promise<boolean>;

  /**
   * Generate a cryptographic-safe value suitable for PKCE.
   *
   * @returns A code verifier to use for PKCE.
   *
   * @see [PKCE](https://docs.fief.dev/going-further/pkce/)
   */
  generateCodeVerifier: () => Promise<string>;

  /**
   * Generate a code challenge from a code verifier for PKCE.
   *
   * @param code - The code verifier.
   * @param method - The hashing method.
   * Can either be `plain` or `S256`. For maximum security, prefer `S256`.
   *
   * @returns A code challenge to use for PKCE.
   *
   * @see [PKCE](https://docs.fief.dev/going-further/pkce/)
   */
  getCodeChallenge: (code: string, method: 'plain' | 'S256') => Promise<string>;
}

export class CryptoHelperError extends Error {}

/**
 * Return a {@link ICryptoHelper} implementation suitable for the current environment.
 *
 * @returns A {@link ICryptoHelper}
 */
export const getCrypto = (): ICryptoHelper => {
  // Browser
  // eslint-disable-next-line no-restricted-globals
  if (typeof window !== 'undefined' || typeof self !== 'undefined') {
    // eslint-disable-next-line global-require
    const { BrowserCryptoHelper } = require('./browser');
    return new BrowserCryptoHelper();
  }

  // NodeJS
  if (typeof require === 'function') {
    // eslint-disable-next-line global-require
    const { NodeJSCryptoHelper } = require('./node');
    return new NodeJSCryptoHelper();
  }

  throw new CryptoHelperError('Cannot find a crypto implementation for your environment');
};
