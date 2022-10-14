/* eslint-disable no-restricted-globals */
import * as crypto from 'crypto';

import { CryptoHelperError, ICryptoHelper } from './base';

class NodeJSCryptoHelperError extends CryptoHelperError { }

export class NodeJSCryptoHelper implements ICryptoHelper {
  private crypto: typeof crypto;

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
    const hashBuffer = this.crypto.createHash('sha256').update(msgBuffer).digest();

    const halfHash = hashBuffer.subarray(0, hashBuffer.byteLength / 2);
    const base64Hash = Buffer.from(new Uint8Array(halfHash)).toString('base64url');

    return base64Hash;
  }

  public async isValidHash(value: string, hash: string): Promise<boolean> {
    const valueHash = await this.getValidationHash(value);
    return valueHash === hash;
  }

  public async generateCodeVerifier(): Promise<string> {
    return new Promise((resolve, reject) => {
      this.crypto.randomBytes(96, (err, buffer) => {
        if (err) {
          reject(err);
        } else {
          resolve(buffer.toString('base64url'));
        }
      });
    });
  }

  public async getCodeChallenge(code: string, method: 'plain' | 'S256'): Promise<string> {
    if (method === 'plain') {
      return code;
    }

    if (method === 'S256') {
      const msgBuffer = new TextEncoder().encode(code);
      return this.crypto.createHash('sha256').update(msgBuffer).digest('base64url');
    }

    throw new CryptoHelperError(`Invalid method "${method}". Allowed methods are: plain, S256`);
  }
}
