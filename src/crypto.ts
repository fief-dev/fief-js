import * as CryptoJS from 'crypto-js';

export const getValidationHash = (value: string): string => {
  const hash = CryptoJS.SHA256(value);

  const halfHash = CryptoJS.lib.WordArray.create(hash.words.slice(0, hash.words.length / 2));
  const base64Hash = CryptoJS.enc.Base64.stringify(halfHash);

  // Remove the Base64 padding "==" at the end
  return base64Hash.slice(0, base64Hash.length - 2);
};

export const isValidHash = (value: string, hash: string): boolean => {
  const valueHash = getValidationHash(value);
  return valueHash === hash;
};
