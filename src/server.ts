/**
 * Common logic for NodeJS HTTP servers.
 *
 * @module
 */
import { IncomingMessage } from 'http';

import {
  Fief,
  FiefAccessTokenExpired,
  FiefAccessTokenInfo,
  FiefAccessTokenInvalid,
  FiefAccessTokenMissingPermission,
  FiefAccessTokenMissingScope,
  FiefError,
  FiefUserInfo,
} from './client';

export class FiefAuthError extends FiefError { }
export class FiefAuthUnauthorized extends FiefAuthError { }
export class FiefAuthForbidden extends FiefAuthError { }

/**
 * Type of a function that can be used to retrieve an access token.
 *
 * @param req — A NodeJS request object.
 *
 * @returns An access token or `null`.
 */
export type TokenGetter<RQ> = (req: RQ) => Promise<string | null>;

/**
 * Interface that should follow a class to implement cache for user data.
 */
export interface IUserInfoCache {
  /**
   * Retrieve user information from cache, if available.
   *
   * @param id - ID of the user to retrieve the user information for.
   *
   * @returns User information or `null`.
   */
  get(id: string): Promise<FiefUserInfo | null>;

  /**
   * Store user information in cache.
   *
   * @param id - ID of the user to store user information for.
   * @param userinfo - The user information to store.
   *
   */
  set(id: string, userinfo: FiefUserInfo): Promise<void>;

  /**
   * Remove user information from cache.
   *
   * @param id - ID of the user to remove the user information for.
   *
   */
  remove(id: string): Promise<void>;

  /**
   * Clear all the user information from cache.
   */
  clear(): Promise<void>;
}

/**
 * Parameters to apply when authenticating a request.
 */
export interface AuthenticateRequestParameters {
  /**
   * If `false` and the request is not authenticated,
   * a {@link FiefAuthUnauthorized} error will be raised.
   */
  optional?: boolean;

  /**
   * Optional list of scopes required.
   * If the access token lacks one of the required scope,
   * a {@link FiefAuthForbidden} error will be raised.
   */
  scope?: string[];

  /**
   * Optional list of permissions required.
   * If the access token lacks one of the required permission,
   * a {@link FiefAuthForbidden} error will be raised.
   */
  permissions?: string[];

  /**
   * If `true`, the user information will be refreshed from the Fief API.
   * Otherwise, the cache will be used.
   */
  refresh?: boolean;
}

/**
 * Data returned after a request has been successfully authenticated.
 */
export interface AuthenticateRequestResult {
  /**
   * Information about the current access token.
   */
  accessTokenInfo: FiefAccessTokenInfo | null;

  /**
   * Current user information.
   */
  user: FiefUserInfo | null;
}

/**
 * Class implementing common logic for authenticating requests in NodeJS servers.
 */
export class FiefAuth<RQ> {
  private client: Fief;

  private tokenGetter: TokenGetter<RQ>;

  private userInfoCache?: IUserInfoCache;

  /**
   * @param client - Instance of a {@link Fief} client.
   * @param tokenGetter - A {@link TokenGetter} function.
   * @param userInfoCache - An instance of a {@link IUserInfoCache} class.
   */
  constructor(client: Fief, tokenGetter: TokenGetter<RQ>, userInfoCache?: IUserInfoCache) {
    this.client = client;
    this.tokenGetter = tokenGetter;
    this.userInfoCache = userInfoCache;
  }

  /**
   * Factory to generate handler for authenticating NodeJS requests.
   *
   * @param parameters - Parameters to apply when authenticating the request.
   *
   * @returns A handler to authenticate NodeJS requests.
   */
  public authenticate(parameters: AuthenticateRequestParameters) {
    return async (req: RQ): Promise<AuthenticateRequestResult> => {
      const {
        optional,
        scope,
        permissions,
        refresh,
      } = parameters;

      const token = await this.tokenGetter(req);
      if (token === null && optional !== true) {
        throw new FiefAuthUnauthorized();
      }

      let accessTokenInfo: FiefAccessTokenInfo | null = null;
      let user: FiefUserInfo | null = null;

      if (token !== null) {
        try {
          accessTokenInfo = await this.client.validateAccessToken(token, scope, permissions);
          if (this.userInfoCache) {
            user = await this.userInfoCache.get(accessTokenInfo.id);
            if (user === null || refresh === true) {
              user = await this.client.userinfo(accessTokenInfo.access_token);
              await this.userInfoCache.set(accessTokenInfo.id, user);
            }
          }
        } catch (err) {
          if (
            !optional
            && (err instanceof FiefAccessTokenInvalid || err instanceof FiefAccessTokenExpired)
          ) {
            throw new FiefAuthUnauthorized();
          } else if (
            err instanceof FiefAccessTokenMissingScope
            || err instanceof FiefAccessTokenMissingPermission
          ) {
            throw new FiefAuthForbidden();
          } else {
            throw err;
          }
        }
      }
      return { accessTokenInfo, user };
    };
  }
}

/**
 * Return a {@link TokenGetter} function retrieving a token
 * from the `Authorization` header of an HTTP request
 * with the specified scheme.
 *
 * @param scheme - Scheme of the token. Defaults to `bearer`.
 *
 * @returns A {@link TokenGetter} function.
 */
export const authorizationSchemeGetter = (scheme: string = 'bearer'): TokenGetter<IncomingMessage> => async (
  req: IncomingMessage,
) => {
  const { authorization } = req.headers;
  if (authorization === undefined) {
    return null;
  }
  const parts = authorization.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== scheme) {
    return null;
  }
  return parts[1];
};

/**
 * Return a {@link TokenGetter} function retrieving a token
 * from a `Cookie` of an HTTP request.
 *
 * @param cookieName - Name of the cookie.
 *
 * @returns A {@link TokenGetter} function.
 */
export const cookieGetter = (cookieName: string): TokenGetter<IncomingMessage> => async (
  req: IncomingMessage,
) => {
  const { cookie: cookieHeader } = req.headers;
  if (cookieHeader === undefined) {
    return null;
  }
  const cookies = cookieHeader.split(';');
  for (let i = 0; i < cookies.length; i += 1) {
    const cookie = cookies[i].trim();
    const semicolonIndex = cookie.indexOf('=');
    const name = cookie.slice(0, semicolonIndex);
    const value = cookie.slice(semicolonIndex + 1);
    if (name === cookieName) {
      return value;
    }
  }
  return null;
};
