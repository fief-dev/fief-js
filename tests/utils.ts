import * as jose from 'jose';
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';

import * as keys from './jwks.json';

const jwks: jose.JSONWebKeySet = keys;
export const signatureKey = jwks.keys.find((key) => key.kid === 'fief-client-tests-sig');
export const signatureKeyPublic = R.pick(['kty', 'use', 'kid', 'n', 'e'], signatureKey);
export const encryptionKey = jwks.keys.find((key) => key.kid === 'fief-client-tests-enc');

export const userId = uuidv4();

export const generateToken = async (
  encrypt: boolean,
  claims?: Record<string, string | number>,
  exp?: number,
): Promise<string> => {
  const signedToken = await new jose
    .SignJWT({ email: 'anne@bretagne.duchy', ...claims ? { ...claims } : {} })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuedAt()
    .setSubject(userId)
    .setIssuer('https://bretagne.fief.dev')
    .setAudience(['CLIENT_ID'])
    .setExpirationTime(exp !== undefined ? exp : '1h')
    ;

  const signatureKeyJWK = await jose.importJWK(signatureKey, 'RS256');
  const signedTokenSerialized = await signedToken.sign(signatureKeyJWK);

  if (encrypt) {
    const encryptedToken = await new jose
      .CompactEncrypt(new TextEncoder().encode(signedTokenSerialized))
      .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256CBC-HS512' })
      ;

    const encryptionKeyJWK = await jose.importJWK(encryptionKey, 'RSA-OAEP-256');
    const encryptedTokenSerialized = await encryptedToken.encrypt(encryptionKeyJWK);
    return encryptedTokenSerialized;
  }

  return signedTokenSerialized;
};
