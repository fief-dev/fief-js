/* eslint-disable no-restricted-globals */
import { Base64 } from 'js-base64';

const getCrypto = (): Crypto => {
  let crypto: Crypto | undefined;

  // Native crypto from window (Browser)
  if (typeof window !== 'undefined' && window.crypto) {
    crypto = window.crypto;
    console.log('From window');
  }

  // Native crypto in web worker (Browser)
  if (typeof self !== 'undefined' && self.crypto) {
    crypto = self.crypto;
    console.log('From web worker');
  }

  // Native crypto from worker
  if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    crypto = globalThis.crypto;
    console.log('From worker');
  }

  // Native crypto from global (NodeJS)
  if (!crypto && typeof global !== 'undefined' && global.crypto) {
    crypto = global.crypto;
    console.log('From global Node');
  }

  // Native crypto import via require (NodeJS)
  if (!crypto && typeof require === 'function') {
    try {
      // eslint-disable-next-line global-require
      crypto = require('crypto');
      console.log('From require');
      // eslint-disable-next-line no-empty
    } catch { }
  }

  if (crypto === undefined) {
    throw new Error('Can\'t initialize the Crypto module');
  }

  return crypto;
};

export const getValidationHash = async (value: string): Promise<string> => {
  const crypto = getCrypto();
  const msgBuffer = new TextEncoder().encode(value);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);

  const halfHash = hashBuffer.slice(0, hashBuffer.byteLength / 2);
  const base64Hash = Base64.fromUint8Array(new Uint8Array(halfHash), true);

  return base64Hash;
};

export const isValidHash = async (value: string, hash: string): Promise<boolean> => {
  const valueHash = await getValidationHash(value);
  return valueHash === hash;
};
