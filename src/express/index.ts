/**
 * Express integration.
 *
 * @module
 */
import { NextFunction, Request, Response } from 'express';

import {
  Fief,
  FiefAccessTokenInfo,
  FiefUserInfo,
} from '../client';
import {
  AuthenticateRequestParameters,
  authorizationSchemeGetter,
  cookieGetter,
  FiefAuth,
  FiefAuthForbidden,
  FiefAuthUnauthorized,
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

/**
 * Default handler for unauthorized response.
 *
 * Set the status code to 401.
 *
 * @param req - An Express `Request` object.
 * @param res  - An Express `Response` object.
 */
const defaultUnauthorizedResponse = async (req: Request, res: Response) => {
  res.status(401).send('Unauthorized');
};

/**
 * Default handler for forbidden response.
 *
 * Set the status code to 403.
 *
 * @param req - An Express `Request` object.
 * @param res  - An Express `Response` object.
 */
const defaultForbiddenResponse = async (req: Request, res: Response) => {
  res.status(403).send('Forbidden');
};

/**
 * Parameters to instantiate a {@link fiefAuth} middleware.
 */
export interface FiefAuthParameters {
  /**
   * Instance of a {@link Fief} client.
   */
  client: Fief;

  /**
   *  {@link TokenGetter} function.
   */
  tokenGetter: TokenGetter<Request>;

  /**
   * An instance of a {@link IUserInfoCache} class.
   */
  userInfoCache?: IUserInfoCache;

  /**
   * Optional handler for unauthorized response.
   *
   * The default handler will return a plain text response with status code 401.
   */
  unauthorizedResponse?: (req: Request, res: Response) => Promise<void>;

  /**
   * Optional handler for forbidden response.
   *
   * The default handler will return a plain text response with status code 403.
   */
  forbiddenResponse?: (req: Request, res: Response) => Promise<void>;
}

/**
 * Return an Express authentication middleware.
 *
 * @param parameters - The middleware parameters.
 *
 * @returns An Express middleware accepting {@link server.AuthenticateRequestParameters} parameters.
 *
 * @example Basic
 * ```ts
 * const fief = require('@fief/fief');
 * const fiefExpress = require('@fief/fief/express');
 * const express = require('express');
 *
 * const fiefClient = new fief.Fief({
 *     baseURL: 'https://example.fief.dev',
 *     clientId: 'YOUR_CLIENT_ID',
 *     clientSecret: 'YOUR_CLIENT_SECRET',
 * });
 * const fiefAuthMiddleware = fiefExpress.createMiddleware({
 *     client: fiefClient,
 *     tokenGetter: fiefExpress.authorizationSchemeGetter(),
 * });
 *
 * const app = express();
 * app.get('/authenticated', fiefAuthMiddleware(), (req, res) => {
 *     res.json(req.accessTokenInfo);
 * });
 * ```
 *
 * @example Required scope
 * ```ts
 * app.get(
 *     '/authenticated-scope',
 *     fiefAuthMiddleware({ scope: ['required_scope'] }),
 *     (req, res) => {
 *         res.json(req.accessTokenInfo);
 *     },
 * );
 * ```
 *
 * @example Required permissions
 * ```ts
 * app.get(
 *     '/authenticated-scope',
 *     fiefAuthMiddleware({ permissions: ['castles:create'] }),
 *     (req, res) => {
 *         res.json(req.accessTokenInfo);
 *     },
 * );
 * ```
 */
const createMiddleware = (parameters: FiefAuthParameters) => {
  const fiefAuthServer = new FiefAuth<Request>(
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
        const { accessTokenInfo, user } = await authenticate(req);
        req.accessTokenInfo = accessTokenInfo;
        req.user = user;
      } catch (err) {
        if (err instanceof FiefAuthUnauthorized) {
          return unauthorizedResponse(req, res);
        }
        if (err instanceof FiefAuthForbidden) {
          return forbiddenResponse(req, res);
        }
      }

      return next();
    };
  };
};

export {
  AuthenticateRequestParameters,
  authorizationSchemeGetter,
  cookieGetter,
  createMiddleware,
  IUserInfoCache,
  TokenGetter,
};
