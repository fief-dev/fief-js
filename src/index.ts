/**
 * Fief client for JavaScript.
 *
 * @module
 */

export * as browser from './browser';
export {
  Fief,
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
