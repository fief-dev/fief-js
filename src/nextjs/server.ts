import { headers } from 'next/headers';

import { FiefAccessTokenInfo, FiefUserInfo } from '../client';

/**
 * Return the user ID set in headers by the Fief middleware, or `null` if not authenticated.
 *
 * This function is suitable for server-side rendering in Next.js.
 *
 * @param headerName - Name of the request header. Defaults to `X-FiefAuth-User-Id`.
 * @returns The user ID, or null if not available.
 */
export const fiefUserId = (headerName: string = 'X-FiefAuth-User-Id'): string | null => {
  const headersList = headers();
  return headersList.get(headerName);
};

/**
 * Return the user information object set in headers by the Fief middleware,
 * or `null` if not authenticated.
 *
 * This function is suitable for server-side rendering in Next.js.
 *
 * @param headerName - Name of the request header. Defaults to `X-FiefAuth-User-Info`.
 * @returns The user information, or null if not available.
 */
export const fiefUserInfo = (headerName: string = 'X-FiefAuth-User-Info'): FiefUserInfo | null => {
  const headersList = headers();
  const rawUserInfo = headersList.get(headerName);
  return rawUserInfo ? JSON.parse(rawUserInfo) : null;
};

/**
 * Return the access token set in headers by the Fief middleware,
 * or `null` if not authenticated.
 *
 * This function is suitable for server-side rendering in Next.js.
 *
 * @param headerName - Name of the request header. Defaults to `X-FiefAuth-Access-Token`.
 * @returns The access token, or null if not available.
 */
export const fiefAccessToken = (headerName: string = 'X-FiefAuth-Access-Token'): string | null => {
  const headersList = headers();
  return headersList.get(headerName);
};

/**
 * Return the access token information set in headers by the Fief middleware,
 * or `null` if not authenticated.
 *
 * This function is suitable for server-side rendering in Next.js.
 *
 * @param headerName - Name of the request header. Defaults to `X-FiefAuth-Access-Token-Info`.
 * @returns The access token information, or null if not available.
 */
export const fiefAccessTokenInfo = (headerName: string = 'X-FiefAuth-Access-Token-Info'): FiefAccessTokenInfo | null => {
  const headersList = headers();
  const rawAccessTokenInfo = headersList.get(headerName);
  return rawAccessTokenInfo ? JSON.parse(rawAccessTokenInfo) : null;
};
