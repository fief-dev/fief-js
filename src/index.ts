/**
 * Fief client for JavaScript.
 *
 * @module
 */

export * as browser from './browser';
export type {
  FiefAccessTokenInfo,
  FiefParameters,
  FiefTokenResponse,
  FiefUserInfo,
} from './client';
export {
  Fief,
  FiefAccessTokenACRTooLow,
  FiefAccessTokenExpired,
  FiefAccessTokenInvalid,
  FiefAccessTokenMissingPermission,
  FiefAccessTokenMissingScope,
  FiefACR,
  FiefError,
  FiefIdTokenInvalid,
  FiefRequestError,
} from './client';
export * as crypto from './crypto';
