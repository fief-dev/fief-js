let subtle: SubtleCrypto;

if (typeof window === 'undefined') {
  const webcrypto = require('crypto').webcrypto;
  subtle = webcrypto.subtle;
} else {
  subtle = window.crypto.subtle;
}

export const getValidationHash = async (value: string): Promise<string> => {
    const msgBuffer = new TextEncoder().encode(value);
    const hashBuffer = await subtle.digest('SHA-256', msgBuffer);

    const halfHash = hashBuffer.slice(0, hashBuffer.byteLength / 2);
    const base64Hash = btoa(String.fromCharCode(...new Uint8Array(halfHash)));

    // Remove the Base64 padding "==" at the end
    return base64Hash.slice(0, base64Hash.length - 2);
};

export const isValidHash = async (value: string, hash: string): Promise<boolean> => {
  const valueHash = await getValidationHash(value);
  return valueHash === hash;
}
