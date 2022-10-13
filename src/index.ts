/**
 * Fief client for JavaScript.
 *
 * @module
 */

export {
  Fief,
  FiefAccessTokenInfo,
  FiefUserInfo,
  FiefAccessTokenExpired,
  FiefAccessTokenInvalid,
  FiefAccessTokenMissingPermission,
  FiefAccessTokenMissingScope,
  FiefError,
  FiefIdTokenInvalid,
  FiefParameters,
  FiefTokenResponse,
} from './client';

export * as browser from './browser';
export * as crypto from './crypto';
export * as express from './express';
export * as nextjs from './nextjs';
export * as server from './server';
