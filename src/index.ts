/**
 * Fief client for JavaScript.
 *
 * @module
 */

export * as browser from './browser';
export {
  Fief,
  FiefAccessTokenACRTooLow,
  FiefAccessTokenExpired,
  FiefAccessTokenInfo,
  FiefAccessTokenInvalid,
  FiefAccessTokenMissingPermission,
  FiefAccessTokenMissingScope,
  FiefACR,
  FiefError,
  FiefIdTokenInvalid,
  FiefParameters,
  FiefRequestError,
  FiefTokenResponse,
  FiefUserInfo,
} from './client';
export * as crypto from './crypto';
