import { Request, Response, NextFunction } from 'express';

import {
  Fief,
  FiefAccessTokenExpired,
  FiefAccessTokenInvalid,
  FiefAccessTokenMissingPermission,
  FiefAccessTokenMissingScope,
  FiefUserInfo,
} from '../client';

interface FiefAuthParameters {
  fief: Fief;
  tokenGetter: (req: Request) => string | null;
  unauthorizedResponse?: (req: Request, res: Response) => void;
  forbiddenResponse?: (req: Request, res: Response) => void;
  getUserInfoCache?: (id: string, req: Request) => FiefUserInfo | null;
  setUserInfoCache?: (id: string, userinfo: FiefUserInfo, req: Request) => void;
}

interface FiefAuthenticatedParameters {
  optional?: boolean;
  scope?: string[];
  permissions?: string[];
  refresh?: boolean;
}

export const authorizationBearerGetter = (req: Request): string | null => {
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

const defaultUnauthorizedResponse = (req: Request, res: Response) => {
  res.status(401).send('Unauthorized');
};

const defaultForbiddenResponse = (req: Request, res: Response) => {
  res.status(403).send('Forbidden');
};

export const fiefAuth = (parameters: FiefAuthParameters) => {
  const {
    fief,
    tokenGetter,
    getUserInfoCache,
    setUserInfoCache,
  } = parameters;

  return (authenticatedParameters: FiefAuthenticatedParameters = {}) => {
    const unauthorizedResponse = (
      parameters.unauthorizedResponse
        ? parameters.unauthorizedResponse
        : defaultUnauthorizedResponse
    );
    const forbiddenResponse = (
      parameters.forbiddenResponse
        ? parameters.forbiddenResponse
        : defaultForbiddenResponse
    );
    const {
      optional,
      scope,
      permissions,
      refresh,
    } = authenticatedParameters;

    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const token = tokenGetter(req);
      if (token === null) {
        if (optional === true) {
          return next();
        }
        return unauthorizedResponse(req, res);
      }

      try {
        const info = await fief.validateAccessToken(token, scope, permissions);
        // @ts-ignore
        req.accessTokenInfo = info;

        let user: FiefUserInfo | null = null;
        if (getUserInfoCache && setUserInfoCache) {
          user = getUserInfoCache(info.id, req);
          if (user === null || refresh === true) {
            user = await fief.userinfo(info.access_token);
            setUserInfoCache(info.id, user, req);
          }
        }
        // @ts-ignore
        req.user = user;
      } catch (err) {
        if (err instanceof FiefAccessTokenInvalid || err instanceof FiefAccessTokenExpired) {
          return unauthorizedResponse(req, res);
        }
        if (
          err instanceof FiefAccessTokenMissingScope
          || err instanceof FiefAccessTokenMissingPermission
        ) {
          return forbiddenResponse(req, res);
        }
        throw err;
      }

      return next();
    };
  };
};
