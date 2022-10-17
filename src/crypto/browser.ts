/* eslint-disable no-restricted-globals */

import { CryptoHelperError, ICryptoHelper } from './base';

class BrowserCryptoHelperError extends CryptoHelperError { }

const toURLSafeBase64 = (buffer: ArrayBuffer): string => btoa(
  String.fromCharCode(...new Uint8Array(buffer)),
)
  .replace(/=/g, '')
  .replace(/[+/]/g, (m0) => (m0 === '+' ? '-' : '_'))
  ;

export class BrowserCryptoHelper implements ICryptoHelper {
  private crypto: Crypto;

  constructor() {
    // Native crypto from window
    if (typeof window !== 'undefined' && window.crypto) {
      this.crypto = window.crypto;
    }

    // Native crypto in web worker (Browser)
    if (typeof self !== 'undefined' && self.crypto) {
      this.crypto = self.crypto;
    }

    // NextJS Edge runtime
    // @ts-ignore
    // eslint-disable-next-line no-undef
    if (typeof EdgeRuntime !== 'undefined' && EdgeRuntime === 'vercel') {
      this.crypto = globalThis.crypto;
    }

    // @ts-ignore
    if (this.crypto === undefined) {
      throw new BrowserCryptoHelperError(
        'Cannot find the Crypto module. Are you sure you are in a browser environment?',
      );
    }
  }

  public async getValidationHash(value: string): Promise<string> {
    const msgBuffer = new TextEncoder().encode(value);
    const hashBuffer = await this.crypto.subtle.digest('SHA-256', msgBuffer);

    const halfHash = hashBuffer.slice(0, hashBuffer.byteLength / 2);
    return toURLSafeBase64(halfHash);
  }

  public async isValidHash(value: string, hash: string): Promise<boolean> {
    const valueHash = await this.getValidationHash(value);
    return valueHash === hash;
  }

  public async generateCodeVerifier(): Promise<string> {
    const randomArray = new Uint8Array(96);
    this.crypto.getRandomValues(randomArray);
    return toURLSafeBase64(randomArray);
  }

  public async getCodeChallenge(code: string, method: 'plain' | 'S256'): Promise<string> {
    if (method === 'plain') {
      return code;
    }

    if (method === 'S256') {
      const msgBuffer = new TextEncoder().encode(code);
      const hashBuffer = await this.crypto.subtle.digest('SHA-256', msgBuffer);
      return toURLSafeBase64(hashBuffer);
    }

    throw new CryptoHelperError(`Invalid method "${method}". Allowed methods are: plain, S256`);
  }
}
