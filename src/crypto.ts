/* eslint-disable no-restricted-globals */
import { Base64 } from 'js-base64';

const getCrypto = (): Crypto => {
  let crypto: Crypto | undefined;

  // Native crypto from window (Browser)
  if (typeof window !== 'undefined' && window.crypto) {
    crypto = window.crypto;
  }

  // Native crypto in web worker (Browser)
  if (typeof self !== 'undefined' && self.crypto) {
    crypto = self.crypto;
  }

  // Native crypto from worker
  if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    crypto = globalThis.crypto;
  }

  // Native crypto from global (NodeJS)
  if (!crypto && typeof global !== 'undefined' && global.crypto) {
    // @ts-ignore
    crypto = global.crypto.webcrypto;
  }

  // Native crypto import via require (NodeJS)
  if (!crypto && typeof require === 'function') {
    try {
      // eslint-disable-next-line global-require
      const cryptoModule = require('crypto');
      crypto = cryptoModule.webcrypto;
      // eslint-disable-next-line no-empty
    } catch { }
  }

  // WebCrypto polyfill for older NodeJS
  try {
    // eslint-disable-next-line global-require
    const { Crypto } = require('@peculiar/webcrypto');
    crypto = new Crypto();
    // eslint-disable-next-line no-empty
  } catch { }

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

export const generateCodeVerifier = async (): Promise<string> => {
  const crypto = getCrypto();
  const randomArray = new Uint8Array(96);
  crypto.getRandomValues(randomArray);
  return Base64.fromUint8Array(randomArray, true);
};

export const getCodeChallenge = async (code: string, method: 'plain' | 'S256'): Promise<string> => {
  if (method === 'plain') {
    return code;
  }

  if (method === 'S256') {
    const crypto = getCrypto();
    const msgBuffer = new TextEncoder().encode(code);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const base64Hash = Base64.fromUint8Array(new Uint8Array(hashBuffer), true);
    return base64Hash;
  }

  throw new Error(`Invalid method "${method}". Allowed methods are: plain, S256`);
};
