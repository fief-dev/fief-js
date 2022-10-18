import httpMocks from 'node-mocks-http';
import { GetServerSidePropsContext, NextApiRequest, NextApiResponse } from 'next';
import { NextRequest } from 'next/server';

import {
  Fief,
  FiefAccessTokenInfo,
  FiefTokenResponse,
  FiefUserInfo,
} from '../client';
import { userId } from '../../tests/utils';
import { FiefAuth } from './index';
import {
  AuthenticateRequestResult,
  FiefAuthForbidden,
  FiefAuthUnauthorized,
  IUserInfoCache,
} from '../server';

class UserInfoCache implements IUserInfoCache {
  private storage: Record<string, any>;

  constructor() {
    this.storage = {};
  }

  async get(id: string): Promise<FiefUserInfo | null> {
    const userinfo = this.storage[id];
    if (userinfo) {
      return userinfo;
    }
    return null;
  }

  async set(id: string, userinfo: FiefUserInfo): Promise<void> {
    this.storage[id] = userinfo;
  }

  async remove(id: string): Promise<void> {
    this.storage[id] = undefined;
  }

  async clear(): Promise<void> {
    this.storage = {};
  }
}

const userInfoCache = new UserInfoCache();

const tokenInfo: FiefTokenResponse = {
  access_token: 'ACCESS_TOKEN',
  expires_in: 3600,
  id_token: 'ID_TOKEN',
  token_type: 'bearer',
};
const authCallbackMock = jest.fn(() => [tokenInfo, { sub: userId }]);

const accessTokenInfo: FiefAccessTokenInfo = {
  id: userId,
  scope: ['openid'],
  permissions: [],
  access_token: 'ACCESS_TOKEN',
};
const validateAccessTokenMock = jest.fn(() => accessTokenInfo);

const userInfoMock = jest.fn(() => ({ sub: userId }));

// @ts-ignore
const fiefMock = jest.fn<Fief, any>(() => ({
  getAuthURL: () => 'https://bretagne.fief.dev/authorize',
  getLogoutURL: () => 'https://bretagne.fief.dev/logout',
  authCallback: authCallbackMock,
  validateAccessToken: validateAccessTokenMock,
  userinfo: userInfoMock,
}));

const fiefAuth = new FiefAuth({
  client: fiefMock(),
  sessionCookieName: 'user_session',
  userInfoCache,
  redirectURI: 'http://localhost:3000/callback',
  logoutRedirectURI: 'http://localhost:3000',
});

const getMockContext = (
  reqOptions?: httpMocks.RequestOptions,
  resOptions?: httpMocks.ResponseOptions,
): GetServerSidePropsContext<any, any> => {
  const { req, res } = httpMocks.createMocks(reqOptions, resOptions);
  return {
    req,
    res,
    query: {},
    resolvedUrl: '',
  };
};

const getMockGetServerSideProps = (): any => jest.fn(() => ({ props: {} }));
const getMockGetServerSidePropsPromise = (): any => jest.fn(
  () => ({
    props: new Promise((resolve) => { resolve({}); }),
  }),
);
const getMockGetServerSidePropsRedirectResult = (): any => jest.fn(() => ({ redirect: {} }));

const getMockAPIContext = (
  reqOptions?: httpMocks.RequestOptions,
  resOptions?: httpMocks.ResponseOptions,
  // @ts-ignore
) => httpMocks.createMocks<NextApiRequest & AuthenticateRequestResult, NextApiResponse>(
  reqOptions,
  resOptions,
);

const getMockNextAPIHandler = (): any => jest.fn((req: NextApiRequest, res: NextApiResponse) => res.status(200).send('OK'));

beforeEach(async () => {
  await userInfoCache.clear();
  userInfoMock.mockClear();
});

describe('middleware', () => {
  const middleware = fiefAuth.middleware([
    {
      matcher: '/authenticated',
      parameters: {},
    },
    {
      matcher: '/authenticated-optional',
      parameters: {
        optional: true,
      },
    },
    {
      matcher: '/authenticated-scope',
      parameters: {
        scope: ['required_scope'],
      },
    },
  ]);

  describe('callback', () => {
    it('should handle authentication callback and redirect to default if no returnTo cookie', async () => {
      const request = new NextRequest('http://localhost:3000/callback');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('http://localhost:3000/');

      expect(response.cookies.get('user_session')).toEqual('ACCESS_TOKEN');
    });

    it('should handle authentication callback and redirect to page set in returnTo cookie', async () => {
      const request = new NextRequest('http://localhost:3000/callback');
      request.cookies.set('return_to', '/return-to');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('http://localhost:3000/return-to');

      expect(response.cookies.get('user_session')).toEqual('ACCESS_TOKEN');
    });
  });

  describe('logout', () => {
    it('should clear session cookie and redirect to Fief logout URL', async () => {
      const request = new NextRequest('http://localhost:3000/logout');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('https://bretagne.fief.dev/logout');

      expect(response.cookies.get('user_session')).toEqual('');
    });
  });

  describe('authentication', () => {
    it('should redirect to Fief authentication URL if no cookie', async () => {
      const request = new NextRequest('http://localhost:3000/authenticated');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('https://bretagne.fief.dev/authorize');

      expect(response.cookies.get('return_to')).toEqual('/authenticated');
    });

    it('should redirect to Fief authentication URL if expired token', async () => {
      validateAccessTokenMock.mockRejectedValueOnce(new FiefAuthUnauthorized() as never);
      const request = new NextRequest('http://localhost:3000/authenticated');
      request.cookies.set('user_session', 'ACCESS_TOKEN');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('https://bretagne.fief.dev/authorize');

      expect(response.cookies.get('return_to')).toEqual('/authenticated');
    });

    it('should return the default response if valid token', async () => {
      const request = new NextRequest('http://localhost:3000/authenticated');
      request.cookies.set('user_session', 'ACCESS_TOKEN');
      const response = await middleware(request);

      expect(response.status).toBe(200);
    });

    it('should return the default response if no token on optional route', async () => {
      const request = new NextRequest('http://localhost:3000/authenticated-optional');
      const response = await middleware(request);

      expect(response.status).toBe(200);
    });

    it('should rewrite to the forbidden page if missing scope or permission', async () => {
      validateAccessTokenMock.mockRejectedValueOnce(new FiefAuthForbidden() as never);
      const request = new NextRequest('http://localhost:3000/authenticated-scope');
      request.cookies.set('user_session', 'ACCESS_TOKEN');
      const response = await middleware(request);

      expect(response.status).toBe(200);
      expect(response.headers.get('x-middleware-rewrite')).toEqual('http://localhost:3000/forbidden');
    });
  });
});

describe('withAuth', () => {
  it('should return a redirection response if no cookie', async () => {
    const context = getMockContext({ method: 'GET' });
    const result = await fiefAuth.withAuth(getMockGetServerSideProps())(context);

    // @ts-ignore
    expect(result.redirect.destination).toMatch('https://bretagne.fief.dev/authorize');
    // @ts-ignore
    expect(result.redirect.permanent).toEqual(false);
  });

  it('should return a redirection response if no matching cookie', async () => {
    const context = getMockContext({ method: 'GET', headers: { cookie: 'foo=bar' } });
    const result = await fiefAuth.withAuth(getMockGetServerSideProps())(context);

    // @ts-ignore
    expect(result.redirect.destination).toMatch('https://bretagne.fief.dev/authorize');
    // @ts-ignore
    expect(result.redirect.permanent).toEqual(false);
  });

  it('should return a redirection response if expired token', async () => {
    validateAccessTokenMock.mockRejectedValueOnce(new FiefAuthUnauthorized() as never);
    const context = getMockContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });
    const result = await fiefAuth.withAuth(getMockGetServerSideProps())(context);

    // @ts-ignore
    expect(result.redirect.destination).toMatch('https://bretagne.fief.dev/authorize');
    // @ts-ignore
    expect(result.redirect.permanent).toEqual(false);
  });

  it('should set accessTokenInfo in props if valid token', async () => {
    const context = getMockContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });
    const result = await fiefAuth.withAuth(getMockGetServerSideProps())(context);

    // @ts-ignore
    expect(result.props.accessTokenInfo).toEqual({
      id: userId,
      scope: ['openid'],
      permissions: [],
      access_token: 'ACCESS_TOKEN',
    });
  });

  it('should set accessTokenInfo in props if valid token with async getServerSideProps', async () => {
    const context = getMockContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });
    const result = await fiefAuth.withAuth(getMockGetServerSidePropsPromise())(context);

    // @ts-ignore
    expect(result.props.accessTokenInfo).toEqual({
      id: userId,
      scope: ['openid'],
      permissions: [],
      access_token: 'ACCESS_TOKEN',
    });
  });

  it('should return raw response with getServerSideProps not returning props', async () => {
    const context = getMockContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });
    const result = await fiefAuth.withAuth(getMockGetServerSidePropsRedirectResult())(context);

    // @ts-ignore
    expect(result).toEqual({ redirect: {} });
  });

  describe('scope', () => {
    it('should set forbidden in props if missing scope', async () => {
      validateAccessTokenMock.mockRejectedValueOnce(new FiefAuthForbidden() as never);
      const context = getMockContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

      const result = await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { scope: ['openid', 'required_scope'] },
      )(context);

      // @ts-ignore
      expect(result.props.forbidden).toEqual(true);
    });

    it('should set accessTokenInfo in props if valid scope', async () => {
      validateAccessTokenMock.mockImplementationOnce(() => ({ ...accessTokenInfo, scope: ['openid', 'required_scope'] }));
      const context = getMockContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

      const result = await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { scope: ['openid', 'required_scope'] },
      )(context);

      // @ts-ignore
      expect(result.props.accessTokenInfo).toEqual({
        id: userId,
        scope: ['openid', 'required_scope'],
        permissions: [],
        access_token: 'ACCESS_TOKEN',
      });
    });
  });

  describe('permission', () => {
    it('should set forbidden in props if missing permission', async () => {
      validateAccessTokenMock.mockRejectedValueOnce(new FiefAuthForbidden() as never);
      const context = getMockContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

      const result = await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { permissions: ['castles:create'] },
      )(context);

      // @ts-ignore
      expect(result.props.forbidden).toEqual(true);
    });

    it('should set accessTokenInfo in props if valid permission', async () => {
      validateAccessTokenMock.mockImplementationOnce(() => ({ ...accessTokenInfo, permissions: ['castles:read', 'castles:create'] }));
      const context = getMockContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

      const result = await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { permissions: ['castles:create'] },
      )(context);

      // @ts-ignore
      expect(result.props.accessTokenInfo).toEqual({
        id: userId,
        scope: ['openid'],
        permissions: ['castles:read', 'castles:create'],
        access_token: 'ACCESS_TOKEN',
      });
    });
  });

  describe('user', () => {
    it('should get userinfo from API and set it in storage', async () => {
      const context = getMockContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });
      const firstResult = await fiefAuth.withAuth(getMockGetServerSideProps())(context);

      // @ts-ignore
      expect(firstResult.props.user).toEqual({ sub: userId });

      const secondResult = await fiefAuth.withAuth(getMockGetServerSideProps())(context);
      // @ts-ignore
      expect(secondResult.props.user).toEqual({ sub: userId });

      expect(userInfoMock).toHaveBeenCalledTimes(1);
    });

    it('should always get userinfo from API if refresh', async () => {
      const context = getMockContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });
      const firstResult = await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { refresh: true },
      )(context);

      // @ts-ignore
      expect(firstResult.props.user).toEqual({ sub: userId });

      await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { refresh: true },
      )(context);

      expect(userInfoMock).toHaveBeenCalledTimes(2);
    });
  });
});

describe('authenticated', () => {
  it('should return 401 if no cookie', async () => {
    const { req, res } = getMockAPIContext({ method: 'GET' });

    await fiefAuth.authenticated(getMockNextAPIHandler())(req, res);

    expect(res.statusCode).toEqual(401);
  });

  it('should return 401 if no matching cookie', async () => {
    const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'foo=bar' } });

    await fiefAuth.authenticated(getMockNextAPIHandler())(req, res);

    expect(res.statusCode).toEqual(401);
  });

  it('should return 401 if expired token', async () => {
    validateAccessTokenMock.mockRejectedValueOnce(new FiefAuthUnauthorized() as never);
    const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

    await fiefAuth.authenticated(getMockNextAPIHandler())(req, res);

    expect(res.statusCode).toEqual(401);
  });

  it('should set accessTokenInfo in Request object if valid token', async () => {
    const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

    await fiefAuth.authenticated(getMockNextAPIHandler())(req, res);

    expect(req.accessTokenInfo).toEqual({
      id: userId,
      scope: ['openid'],
      permissions: [],
      access_token: 'ACCESS_TOKEN',
    });
  });

  describe('optional', () => {
    it('should not throw 401 if no token', async () => {
      const { req, res } = getMockAPIContext({ method: 'GET' });

      await fiefAuth.authenticated(getMockNextAPIHandler(), { optional: true })(req, res);

      expect(res.statusCode).toEqual(200);
    });

    it('should set accessTokenInfo in Request object if valid token', async () => {
      const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

      await fiefAuth.authenticated(getMockNextAPIHandler(), { optional: true })(req, res);

      expect(req.accessTokenInfo).toEqual({
        id: userId,
        scope: ['openid'],
        permissions: [],
        access_token: 'ACCESS_TOKEN',
      });
    });
  });

  describe('scope', () => {
    it('should throw 403 if missing scope', async () => {
      validateAccessTokenMock.mockRejectedValueOnce(new FiefAuthForbidden() as never);
      const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

      await fiefAuth.authenticated(getMockNextAPIHandler(), { scope: ['required_scope'] })(req, res);

      expect(res.statusCode).toEqual(403);
    });

    it('should set accessTokenInfo in Request object if valid scope', async () => {
      validateAccessTokenMock.mockImplementationOnce(() => ({ ...accessTokenInfo, scope: ['openid', 'required_scope'] }));
      const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

      await fiefAuth.authenticated(getMockNextAPIHandler(), { scope: ['required_scope'] })(req, res);

      expect(req.accessTokenInfo).toEqual({
        id: userId,
        scope: ['openid', 'required_scope'],
        permissions: [],
        access_token: 'ACCESS_TOKEN',
      });
    });
  });

  describe('permission', () => {
    it('should throw 403 if missing permission', async () => {
      validateAccessTokenMock.mockRejectedValueOnce(new FiefAuthForbidden() as never);
      const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

      await fiefAuth.authenticated(getMockNextAPIHandler(), { permissions: ['castles:create'] })(req, res);

      expect(res.statusCode).toEqual(403);
    });

    it('should set accessTokenInfo in Request object if valid permission', async () => {
      validateAccessTokenMock.mockImplementationOnce(() => ({ ...accessTokenInfo, permissions: ['castles:read', 'castles:create'] }));
      const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });
      await fiefAuth.authenticated(getMockNextAPIHandler(), { permissions: ['castles:create'] })(req, res);

      expect(req.accessTokenInfo).toEqual({
        id: userId,
        scope: ['openid'],
        permissions: ['castles:read', 'castles:create'],
        access_token: 'ACCESS_TOKEN',
      });
    });
  });

  describe('user', () => {
    it('should get userinfo from API and set it in storage', async () => {
      const { req: firstReq, res: firstRes } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

      await fiefAuth.authenticated(getMockNextAPIHandler())(firstReq, firstRes);
      expect(firstReq.user).toEqual({ sub: userId });

      const { req: secondReq, res: secondRes } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });
      await fiefAuth.authenticated(getMockNextAPIHandler())(secondReq, secondRes);
      expect(secondReq.user).toEqual({ sub: userId });

      expect(userInfoMock).toHaveBeenCalledTimes(1);
    });

    it('should always get userinfo from API if refresh', async () => {
      const { req: firstReq, res: firstRes } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });
      await fiefAuth.authenticated(
        getMockNextAPIHandler(),
        { refresh: true },
      )(firstReq, firstRes);
      expect(firstReq.user).toEqual({ sub: userId });

      const { req: secondReq, res: secondRes } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });
      await fiefAuth.authenticated(
        getMockNextAPIHandler(),
        { refresh: true },
      )(secondReq, secondRes);
      expect(secondReq.user).toEqual({ sub: userId });

      expect(userInfoMock).toHaveBeenCalledTimes(2);
    });
  });
});
