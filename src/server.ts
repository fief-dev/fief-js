import { IncomingMessage, OutgoingMessage } from 'http';

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

export class FiefServerError extends FiefError { }
export class FiefUnauthorizedError extends FiefServerError { }
export class FiefForbiddenError extends FiefServerError { }

export type TokenGetter<RQ extends IncomingMessage> = (req: RQ) => Promise<string | null>;

export interface IUserInfoCache<RQ extends IncomingMessage, RS extends OutgoingMessage> {
  get(
    id: string,
    req: RQ,
    res: RS,
  ): Promise<FiefUserInfo | null>;
  set(id: string,
    userinfo: FiefUserInfo,
    req: RQ,
    res: RS,
  ): Promise<void>;
  remove(
    id: string,
    req: RQ,
    res: RS,
  ): Promise<void>;
  clear(
    req: RQ,
    res: RS,
  ): Promise<void>;
}

export interface AuthenticateRequestParameters {
  optional?: boolean;
  scope?: string[];
  permissions?: string[];
  refresh?: boolean;
}

export interface AuthenticateRequestResult {
  accessTokenInfo: FiefAccessTokenInfo | null;
  user: FiefUserInfo | null;
}

export class FiefAuth<RQ extends IncomingMessage, RS extends OutgoingMessage> {
  private client: Fief;

  private tokenGetter: TokenGetter<RQ>;

  private userInfoCache?: IUserInfoCache<RQ, RS>;

  constructor(client: Fief, tokenGetter: TokenGetter<RQ>, userInfoCache?: IUserInfoCache<RQ, RS>) {
    this.client = client;
    this.tokenGetter = tokenGetter;
    this.userInfoCache = userInfoCache;
  }

  public authenticate(parameters: AuthenticateRequestParameters) {
    return async (
      req: RQ,
      res: RS,
    ): Promise<AuthenticateRequestResult> => {
      const {
        optional,
        scope,
        permissions,
        refresh,
      } = parameters;

      const token = await this.tokenGetter(req);
      if (token === null && optional !== true) {
        throw new FiefUnauthorizedError();
      }

      let accessTokenInfo: FiefAccessTokenInfo | null = null;
      let user: FiefUserInfo | null = null;

      if (token !== null) {
        try {
          accessTokenInfo = await this.client.validateAccessToken(token, scope, permissions);
          if (this.userInfoCache) {
            user = await this.userInfoCache.get(accessTokenInfo.id, req, res);
            if (user === null || refresh === true) {
              user = await this.client.userinfo(accessTokenInfo.access_token);
              await this.userInfoCache.set(accessTokenInfo.id, user, req, res);
            }
          }
        } catch (err) {
          if (err instanceof FiefAccessTokenInvalid || err instanceof FiefAccessTokenExpired) {
            throw new FiefUnauthorizedError();
          }
          if (
            err instanceof FiefAccessTokenMissingScope
            || err instanceof FiefAccessTokenMissingPermission
          ) {
            throw new FiefForbiddenError();
          }
          throw err;
        }
      }
      return { accessTokenInfo, user };
    };
  }
}

export const authorizationBearerGetter: TokenGetter<IncomingMessage> = async (
  req: IncomingMessage,
) => {
  const { authorization } = req.headers;
  if (authorization === undefined) {
    return null;
  }
  const parts = authorization.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }
  return parts[1];
};
