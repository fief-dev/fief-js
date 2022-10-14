/* eslint-disable no-restricted-globals */
import * as crypto from 'crypto';

import { CryptoHelperError, ICryptoHelper } from './index';

class NodeJSCryptoHelperError extends CryptoHelperError {}

export class NodeJSCryptoHelper implements ICryptoHelper {
  private crypto: Crypto;

  constructor() {
    this.crypto = crypto;
    if (this.crypto === undefined) {
      throw new NodeJSCryptoHelperError(
        'Cannot find the Crypto module. Are you sure you are in a browser environment?',
      );
    }
  }

  public async getValidationHash(value: string): Promise<string> {
    const msgBuffer = new TextEncoder().encode(value);
    const hashBuffer = await this.crypto.subtle.digest('SHA-256', msgBuffer);

    const halfHash = hashBuffer.slice(0, hashBuffer.byteLength / 2);
    const base64Hash = Buffer.from(new Uint8Array(halfHash)).toString('base64url');

    return base64Hash;
  }

  public async isValidHash(value: string, hash: string): Promise<boolean> {
    const valueHash = await this.getValidationHash(value);
    return valueHash === hash;
  }

  public async generateCodeVerifier(): Promise<string> {
    const randomArray = new Uint8Array(96);
    this.crypto.getRandomValues(randomArray);
    return Buffer.from(randomArray).toString('base64url');
  }

  public async getCodeChallenge(code: string, method: 'plain' | 'S256'): Promise<string> {
    if (method === 'plain') {
      return code;
    }

    if (method === 'S256') {
      const msgBuffer = new TextEncoder().encode(code);
      const hashBuffer = await this.crypto.subtle.digest('SHA-256', msgBuffer);
      const base64Hash = Buffer.from(new Uint8Array(hashBuffer)).toString('base64url');
      return base64Hash;
    }

    throw new CryptoHelperError(`Invalid method "${method}". Allowed methods are: plain, S256`);
  }
}
