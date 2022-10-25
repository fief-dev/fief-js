/**
 * NextJS integration.
 *
 * @module
 */
import { IncomingMessage, OutgoingMessage } from 'http';
import type { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { pathToRegexp } from 'path-to-regexp';

import {
  Fief,
  FiefAccessTokenInfo,
  FiefSafeAccessTokenInfo,
  FiefUserInfo,
} from '../client';
import {
  AuthenticateRequestParameters,
  AuthenticateRequestResult,
  FiefAuth as FiefAuthServer,
  FiefAuthForbidden,
  FiefAuthUnauthorized,
  IUserInfoCache,
  cookieGetter,
} from '../server';
import {
  FiefAuthContext,
  FiefAuthProvider,
  FiefAuthProviderProps,
  useFiefAccessTokenInfo,
  useFiefIsAuthenticated,
  useFiefRefresh,
  useFiefUserinfo,

} from './react';

const defaultAPIUnauthorizedResponse = async (req: NextApiRequest, res: NextApiResponse) => {
  res.status(401).send('Unauthorized');
};

const defaultAPIForbiddenResponse = async (req: NextApiRequest, res: NextApiResponse) => {
  res.status(403).send('Forbidden');
};

type FiefNextApiHandler<T> = (
  req: NextApiRequest & AuthenticateRequestResult,
  res: NextApiResponse<T>,
) => unknown | Promise<unknown>;

/**
 * Parameters to instantiate a {@link FiefAuth} helper class.
 */
export interface FiefAuthParameters {
  /**
   * Instance of a {@link Fief} client.
   */
  client: Fief;

  /**
   * Name of the cookie that will keep the session.
   */
  sessionCookieName: string;

  /**
   * Absolute callback URI where the user
   * will be redirected after Fief authentication.
   *
   * **Example:** `http://localhost:3000/callback`
   */
  redirectURI: string;

  /**
   * Path to the callback page where the user
   * will be redirected after Fief authentication.
   *
   * Defaults to `/callback`.
   */
  redirectPath?: string;

  /**
   * Absolute callback URI where the user
   * will be redirected after Fief logout.
   *
   * **Example:** `http://localhost:3000`
   */
  logoutRedirectURI: string;

  /**
   * Path to the logout page.
   *
   * Defaults to `/logout`.
   */
  logoutPath?: string;

  /**
   * Name of the cookie that will keep the page the user
   * was trying to access while unauthenticated.
   *
   * It allows to automatically redirect the user to the page
   * they were looking for after a successul authentication.
   *
   * Defaults to `return_to`.
   */
  returnToCookieName?: string;

  /**
   * Path where the user will be redirected by default
   * after a successfull authentication if there is
   * not `returnTo` cookie.
   *
   * Defaults to `/`.
   */
  returnToDefault?: string;

  /**
   * Path of the page showing a forbidden error to the user.
   *
   * This page will be shown when the user doesn't have the required
   * scope or permissions.
   *
   * Defaults to `/forbidden`.
   */
  forbiddenPath?: string;

  /**
   * An instance of a {@link IUserInfoCache} class.
   */
  userInfoCache?: IUserInfoCache;

  /**
   * Optional API handler for unauthorized response.
   *
   * The default handler will return a plain text response with status code 401.
   */
  apiUnauthorizedResponse?: (req: IncomingMessage, res: OutgoingMessage) => Promise<void>;

  /**
   * Optional API handler for forbidden response.
   *
   * The default handler will return a plain text response with status code 403.
   */
  apiForbiddenResponse?: (req: IncomingMessage, res: OutgoingMessage) => Promise<void>;
}

export interface PathConfig {
  /**
   * A string to match the path.
   *
   * It follows the same syntax as NextJS paths matching.
   *
   * @see [Matching paths](https://nextjs.org/docs/advanced-features/middleware#matcher)
   */
  matcher: string;

  /**
   * Parameters to apply when authenticating the request on this matched path.
   */
  parameters: AuthenticateRequestParameters;
}

/**
 * Helper class to integrate Fief authentication with NextJS.
 *
 * @example Basic
 * ```ts
 * import { Fief, FiefUserInfo } from '@fief/fief';
 * import { FiefAuth, IUserInfoCache } from '@fief/fief/nextjs';
 *
 * export const SESSION_COOKIE_NAME = "user_session";
 *
 * const fiefClient = new fief.Fief({
 *     baseURL: 'https://example.fief.dev',
 *     clientId: 'YOUR_CLIENT_ID',
 *     clientSecret: 'YOUR_CLIENT_SECRET',
 * });
 *
 * export const fiefAuth = new FiefAuth({
 *   client: fiefClient,
 *   sessionCookieName: SESSION_COOKIE_NAME,
 *   redirectURI: 'http://localhost:3000/callback',
 *   logoutRedirectURI: 'http://localhost:3000',
 *   userInfoCache: new UserInfoCache(),
 * });
 * ```
 */
class FiefAuth {
  private client: Fief;

  private fiefAuth: FiefAuthServer<IncomingMessage>;

  private fiefAuthEdge: FiefAuthServer<NextRequest>;

  private userInfoCache?: IUserInfoCache;

  private sessionCookieName: string;

  private redirectURI: string;

  private redirectPath: string;

  private logoutRedirectURI: string;

  private logoutPath: string;

  private returnToCookieName: string;

  private returnToDefault: string;

  private forbiddenPath: string;

  private apiUnauthorizedResponse: (req: NextApiRequest, res: NextApiResponse) => Promise<void>;

  private apiForbiddenResponse: (req: NextApiRequest, res: NextApiResponse) => Promise<void>;

  constructor(parameters: FiefAuthParameters) {
    this.client = parameters.client;

    this.fiefAuth = new FiefAuthServer(
      parameters.client,
      cookieGetter(parameters.sessionCookieName),
      parameters.userInfoCache,
    );
    this.fiefAuthEdge = new FiefAuthServer(
      parameters.client,
      async (request) => request.cookies.get(parameters.sessionCookieName) || null,
      parameters.userInfoCache,
    );

    this.userInfoCache = parameters.userInfoCache;

    this.sessionCookieName = parameters.sessionCookieName;

    this.redirectURI = parameters.redirectURI;
    this.redirectPath = parameters.redirectPath ? parameters.redirectPath : '/callback';

    this.logoutRedirectURI = parameters.logoutRedirectURI;
    this.logoutPath = parameters.logoutPath ? parameters.logoutPath : '/logout';

    this.returnToCookieName = parameters.returnToCookieName ? parameters.returnToCookieName : 'return_to';
    this.returnToDefault = parameters.returnToDefault ? parameters.returnToDefault : '/';

    this.forbiddenPath = parameters.forbiddenPath ? parameters.forbiddenPath : '/forbidden';

    this.apiUnauthorizedResponse = parameters.apiUnauthorizedResponse
      ? parameters.apiUnauthorizedResponse
      : defaultAPIUnauthorizedResponse
    ;
    this.apiForbiddenResponse = parameters.apiForbiddenResponse
      ? parameters.apiForbiddenResponse
      : defaultAPIForbiddenResponse
    ;
  }

  /**
   * Return a NextJS middleware to control authentication on the specified paths.
   *
   * @param pathsConfig - A list of paths matchers with their authentication parameters.
   * @returns A NextJS middleware function.
   * @see [NextJS Middleware](https://nextjs.org/docs/advanced-features/middleware)
   *
   * @example
   * ```ts
   * import type { NextRequest } from 'next/server'
   *
   * import { fiefAuth } from './fief'
   *
   * const authMiddleware = fiefAuth.middleware([
   *   {
   *     matcher: '/private',
   *     parameters: {},
   *   },
   *   {
   *     matcher: '/app/:path*',
   *     parameters: {},
   *   },
   *   {
   *     matcher: '/scope',
   *     parameters: {
   *         scope: ['required_scope']
   *     },
   *   },
   *   {
   *     matcher: '/permission',
   *     parameters: {
   *         permissions: ['castles:create']
   *     },
   *   },
   * ]);
   *
   * export async function middleware(request: NextRequest) {
   *   return authMiddleware(request);
   * };
   * ```
   */
  public middleware(pathsConfig: PathConfig[]) {
    const compiledPathsAuthenticators = pathsConfig.map(({ matcher, parameters }) => ({
      matcher: pathToRegexp(matcher),
      authenticate: this.fiefAuthEdge.authenticate(parameters),
    }));
    return async (request: NextRequest): Promise<NextResponse> => {
      // Handle authentication callback
      if (request.nextUrl.pathname === this.redirectPath) {
        const code = request.nextUrl.searchParams.get('code');
        const [tokens] = await this.client.authCallback(code as string, this.redirectURI);

        const returnTo = request.cookies.get(this.returnToCookieName);
        const redirectURL = new URL(returnTo || this.returnToDefault, request.url);
        const response = NextResponse.redirect(redirectURL);
        response.cookies.set(
          this.sessionCookieName,
          tokens.access_token,
          {
            maxAge: tokens.expires_in,
            httpOnly: true,
            secure: false,
          },
        );
        response.cookies.set(this.returnToCookieName, '', { maxAge: 0 });

        return response;
      }

      // Handle logout
      if (request.nextUrl.pathname === this.logoutPath) {
        const logoutURL = await this.client.getLogoutURL({ redirectURI: this.logoutRedirectURI });
        const response = NextResponse.redirect(logoutURL);
        response.cookies.set(this.sessionCookieName, '', { maxAge: 0 });
        return response;
      }

      // Check authentication for configured paths
      for (let i = 0; i < compiledPathsAuthenticators.length; i += 1) {
        const { matcher, authenticate } = compiledPathsAuthenticators[i];
        if (matcher.exec(request.nextUrl.pathname)) {
          try {
            // eslint-disable-next-line no-await-in-loop
            await authenticate(request);
          } catch (err) {
            if (err instanceof FiefAuthUnauthorized) {
              // eslint-disable-next-line no-await-in-loop
              const authURL = await this.client.getAuthURL({ redirectURI: this.redirectURI, scope: ['openid'] });

              const response = NextResponse.redirect(authURL);
              response.cookies.set(this.returnToCookieName, request.nextUrl.pathname);

              return response;
            }
            if (err instanceof FiefAuthForbidden) {
              return NextResponse.rewrite(new URL(this.forbiddenPath, request.url));
            }
          }
        }
      }

      // Default response
      return NextResponse.next();
    };
  }

  /**
   * Return an API middleware to authenticate an API route.
   *
   * @param route - Your API route handler.
   * @param authenticatedParameters - Optional parameters to apply when authenticating the request.
   * @returns An API handler.
   * @see [NextJS API Routes](https://nextjs.org/docs/api-routes/introduction)
   *
   * @example Basic
   * ```ts
   * import { fiefAuth } from "../../fief"
   *
   * export default fiefAuth.authenticated(function handler(req, res) {
   *     res.status(200).json(req.user);
   * });
   * ```
   *
   * @example Required scope
   * ```ts
   * import { fiefAuth } from "../../fief"
   *
   * export default fiefAuth.authenticated(function handler(req, res) {
   *     res.status(200).json(req.user);
   * }, { scope: ['required_scope'] });
   * ```
   *
   * @example Required permissions
   * ```ts
   * import { fiefAuth } from "../../fief"
   *
   * export default fiefAuth.authenticated(function handler(req, res) {
   *     res.status(200).json(req.user);
   * }, { permissions: ['castles:create'] });
   * ```
   */
  public authenticated<T>(
    route: FiefNextApiHandler<T>,
    authenticatedParameters: AuthenticateRequestParameters = {},
  ): FiefNextApiHandler<T> {
    const authenticate = this.fiefAuth.authenticate(authenticatedParameters);
    return async (req: NextApiRequest & AuthenticateRequestResult, res: NextApiResponse) => {
      let user: FiefUserInfo | null = null;
      let accessTokenInfo: FiefAccessTokenInfo | null = null;
      try {
        const result = await authenticate(req);
        user = result.user;
        accessTokenInfo = result.accessTokenInfo;
      } catch (err) {
        if (err instanceof FiefAuthUnauthorized) {
          return this.apiUnauthorizedResponse(req, res);
        }
        if (err instanceof FiefAuthForbidden) {
          return this.apiForbiddenResponse(req, res);
        }
      }

      req.accessTokenInfo = accessTokenInfo;
      req.user = user;
      return route(req, res);
    };
  }

  /**
   * Return an API route to get the {@link FiefUserInfo} and {@link FiefAccessTokenInfo}
   * of the currently authenticated user.
   *
   * It's mainly useful to get the user information from the React hooks.
   *
   * @returns An API route.
   *
   * @example
   * ```
   * import { fiefAuth } from '../../fief';
   *
   * export default fiefAuth.currentUser();
   * ```
   */
  public currentUser(): FiefNextApiHandler<{
    userinfo: FiefUserInfo | null,
    access_token_info: FiefSafeAccessTokenInfo | null,
  }> {
    return this.authenticated(
      async (req, res) => {
        let safeAccessTokenInfo: FiefSafeAccessTokenInfo | null = null;
        if (req.accessTokenInfo) {
          const { access_token: _, ...rest } = req.accessTokenInfo;
          safeAccessTokenInfo = rest;
        }
        res.status(200).json({ userinfo: req.user, access_token_info: safeAccessTokenInfo });
      },
      { optional: true },
    );
  }
}

export {
  AuthenticateRequestParameters,
  IUserInfoCache,
  FiefAuth,
  FiefAuthContext,
  FiefAuthProvider,
  FiefAuthProviderProps,
  useFiefAccessTokenInfo,
  useFiefIsAuthenticated,
  useFiefRefresh,
  useFiefUserinfo,
};
