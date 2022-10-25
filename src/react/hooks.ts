import { useContext } from 'react';

import type { FiefAuth } from '../browser';
import type { FiefTokenResponse, FiefUserInfo } from '../client';
import { FiefAuthContext } from './context';

/**
 * Return an instance of the {@link index.browser.FiefAuth} browser helper.
 *
 * @returns The {@link index.browser.FiefAuth} browser helper.
 *
 * @example
 * ```tsx
 * const fiefAuth = useFiefAuth();
 * ```
 */
export const useFiefAuth = (): FiefAuth => {
  const { auth } = useContext(FiefAuthContext);
  return auth;
};

/**
 * Return the user information object available in session, or `null` if no current session.
 *
 * @returns The user information, or null if not available.
 *
 * @example
 * ```tsx
 * const userinfo = useFiefUserinfo();
 * ````
 */
export const useFiefUserinfo = (): FiefUserInfo | null => {
  const { state } = useContext(FiefAuthContext);
  return state.userinfo;
};

/**
 * Return the token information object available in session, or `null` if no current session.
 *
 * @returns The token information, or null if not available.
 *
 * @example
 * ```tsx
 * const tokenInfo = useFiefTokenInfo();
 * ```
 */
export const useFiefTokenInfo = (): FiefTokenResponse | null => {
  const { state } = useContext(FiefAuthContext);
  return state.tokenInfo;
};

/**
 * Return whether there is a valid user session.
 *
 * @returns `true` if there is a valid user session, `false` otherwise.
 *
 * @example
 * ```tsx
 * const isAuthenticated = useFiefIsAuthenticated();
 * ```
 */
export const useFiefIsAuthenticated = (): boolean => {
  const userinfo = useFiefUserinfo();
  return userinfo !== null;
};
