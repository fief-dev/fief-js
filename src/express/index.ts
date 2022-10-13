import { Request, Response, NextFunction } from 'express';

import {
  Fief,
  FiefAccessTokenInfo,
  FiefUserInfo,
} from '../client';
import {
  AuthenticateRequestParameters,
  FiefAuth,
  FiefForbiddenError,
  FiefUnauthorizedError,
  IUserInfoCache,
  TokenGetter,
} from '../server';

declare global {
  namespace Express {
    // eslint-disable-next-line no-shadow
    interface Request {
      accessTokenInfo: FiefAccessTokenInfo | null;
      user: FiefUserInfo | null;
    }
  }
}

const defaultUnauthorizedResponse = async (req: Request, res: Response) => {
  res.status(401).send('Unauthorized');
};

const defaultForbiddenResponse = async (req: Request, res: Response) => {
  res.status(403).send('Forbidden');
};

interface FiefAuthParameters {
  client: Fief;
  tokenGetter: TokenGetter<Request>;
  userInfoCache?: IUserInfoCache<Request, Response>;
  unauthorizedResponse?: (req: Request, res: Response) => Promise<void>;
  forbiddenResponse?: (req: Request, res: Response) => Promise<void>;
}

export const fiefAuth = (parameters: FiefAuthParameters) => {
  const fiefAuthServer = new FiefAuth<Request, Response>(
    parameters.client,
    parameters.tokenGetter,
    parameters.userInfoCache,
  );
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

  return (authenticatedParameters: AuthenticateRequestParameters = {}) => {
    const authenticate = fiefAuthServer.authenticate(authenticatedParameters);
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      req.accessTokenInfo = null;
      req.user = null;

      try {
        const { accessTokenInfo, user } = await authenticate(req, res);
        req.accessTokenInfo = accessTokenInfo;
        req.user = user;
      } catch (err) {
        if (err instanceof FiefUnauthorizedError) {
          return unauthorizedResponse(req, res);
        }
        if (err instanceof FiefForbiddenError) {
          return forbiddenResponse(req, res);
        }
      }

      return next();
    };
  };
};
