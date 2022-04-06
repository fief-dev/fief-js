import * as CryptoJS from 'crypto-js';

export const getValidationHash = (value: string): string => {
  const hash = CryptoJS.SHA256(value);

  const halfHash = CryptoJS.lib.WordArray.create(hash.words.slice(0, hash.words.length / 2));
  const base64Hash = CryptoJS.enc.Base64url.stringify(halfHash);

  return base64Hash;
};

export const isValidHash = (value: string, hash: string): boolean => {
  const valueHash = getValidationHash(value);
  return valueHash === hash;
};
