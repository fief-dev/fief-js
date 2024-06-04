/**
 * React integration.
 *
 * @module
 */

import { FiefAuthContext } from './context';
import {
  useFiefAuth,
  useFiefIsAuthenticated,
  useFiefTokenInfo,
  useFiefUserinfo,
} from './hooks';
import { FiefAuthProvider, FiefAuthProviderProps } from './provider';
import { FiefAuthState } from './storage';

export {
  FiefAuthContext,
  FiefAuthProvider,
  useFiefAuth,
  useFiefIsAuthenticated,
  useFiefTokenInfo,
  useFiefUserinfo,
};
export type {
  FiefAuthProviderProps,
  FiefAuthState,
};
