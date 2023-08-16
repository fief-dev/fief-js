import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest } from 'next/server';
import httpMocks from 'node-mocks-http';

import { userId } from '../../tests/utils';
import {
  Fief,
  FiefAccessTokenExpired,
  FiefAccessTokenInfo,
  FiefAccessTokenMissingPermission,
  FiefAccessTokenMissingScope,
  FiefTokenResponse,
  FiefUserInfo,
} from '../client';
import { AuthenticateRequestResult, IUserInfoCache } from '../server';
import { FiefAuth } from './index';

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
  redirectURI: 'http://localhost:3000/auth-callback',
  logoutRedirectURI: 'http://localhost:3000',
});

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
    {
      matcher: '/authenticated-permission',
      parameters: {
        permissions: ['castles:create'],
      },
    },
  ]);

  describe('login', () => {
    it('should redirect to Fief authentication URL', async () => {
      const request = new NextRequest('http://localhost:3000/login');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('https://bretagne.fief.dev/authorize');
    });
  });

  describe('callback', () => {
    it('should handle authentication callback and redirect to default if no returnTo cookie', async () => {
      const request = new NextRequest('http://localhost:3000/auth-callback');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('http://localhost:3000/');

      expect(response.cookies.get('user_session')?.value).toEqual('ACCESS_TOKEN');
    });

    it('should handle authentication callback and redirect to page set in returnTo cookie', async () => {
      const request = new NextRequest('http://localhost:3000/auth-callback');
      request.cookies.set('return_to', '/return-to');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('http://localhost:3000/return-to');

      expect(response.cookies.get('user_session')?.value).toEqual('ACCESS_TOKEN');
    });
  });

  describe('logout', () => {
    it('should do nothing and just return empty response on prefetch', async () => {
      const request = new NextRequest('http://localhost:3000/logout', { headers: { 'X-Middleware-Prefetch': '1' } });
      const response = await middleware(request);

      expect(response.status).toBe(204);

      expect(response.cookies.get('user_session')).toBeUndefined();
    });

    it('should clear session cookie and redirect to Fief logout URL', async () => {
      const request = new NextRequest('http://localhost:3000/logout');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('https://bretagne.fief.dev/logout');

      expect(response.cookies.get('user_session')?.value).toEqual('');
    });
  });

  describe('authentication', () => {
    it('should redirect to Fief authentication URL if no cookie', async () => {
      const request = new NextRequest('http://localhost:3000/authenticated');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('https://bretagne.fief.dev/authorize');

      expect(response.cookies.get('return_to')?.value).toEqual('/authenticated');
    });

    it('should redirect to Fief authentication URL if expired token', async () => {
      validateAccessTokenMock.mockRejectedValueOnce(new FiefAccessTokenExpired() as never);
      const request = new NextRequest('http://localhost:3000/authenticated');
      request.cookies.set('user_session', 'ACCESS_TOKEN');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('https://bretagne.fief.dev/authorize');

      expect(response.cookies.get('return_to')?.value).toEqual('/authenticated');
    });

    it('should preserve query parameters in return_to URL', async () => {
      validateAccessTokenMock.mockRejectedValueOnce(new FiefAccessTokenExpired() as never);
      const request = new NextRequest('http://localhost:3000/authenticated?query1=value1&query2=value2');
      request.cookies.set('user_session', 'ACCESS_TOKEN');
      const response = await middleware(request);

      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toEqual('https://bretagne.fief.dev/authorize');

      expect(response.cookies.get('return_to')?.value).toEqual('/authenticated?query1=value1&query2=value2');
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

    it('should rewrite to the forbidden page if missing scope', async () => {
      validateAccessTokenMock.mockRejectedValueOnce(new FiefAccessTokenMissingScope() as never);
      const request = new NextRequest('http://localhost:3000/authenticated-scope');
      request.cookies.set('user_session', 'ACCESS_TOKEN');
      const response = await middleware(request);

      expect(response.status).toBe(200);
      expect(response.headers.get('x-middleware-rewrite')).toEqual('http://localhost:3000/forbidden');
    });

    it('should rewrite to the forbidden page if missing permission', async () => {
      validateAccessTokenMock.mockRejectedValueOnce(
        new FiefAccessTokenMissingPermission() as never,
      );
      const request = new NextRequest('http://localhost:3000/authenticated-permission');
      request.cookies.set('user_session', 'ACCESS_TOKEN');
      const response = await middleware(request);

      expect(response.status).toBe(200);
      expect(response.headers.get('x-middleware-rewrite')).toEqual('http://localhost:3000/forbidden');
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
    validateAccessTokenMock.mockRejectedValueOnce(new FiefAccessTokenExpired() as never);
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

    it('should not throw 401 if expired token', async () => {
      validateAccessTokenMock.mockRejectedValueOnce(new FiefAccessTokenExpired() as never);
      const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

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
      validateAccessTokenMock.mockRejectedValueOnce(new FiefAccessTokenMissingScope() as never);
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
      validateAccessTokenMock.mockRejectedValueOnce(
        new FiefAccessTokenMissingPermission() as never,
      );
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

describe('currentUser', () => {
  it('should return null userinfo if no cookie', async () => {
    const { req, res } = getMockAPIContext({ method: 'GET' });

    await fiefAuth.currentUser()(req, res);

    expect(res.statusCode).toEqual(200);
  });

  it('should return null userinfo if no matching cookie', async () => {
    const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'foo=bar' } });

    await fiefAuth.currentUser()(req, res);

    expect(res.statusCode).toEqual(200);
  });

  it('should return null userinfo if expired token', async () => {
    validateAccessTokenMock.mockRejectedValueOnce(new FiefAccessTokenExpired() as never);
    const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

    await fiefAuth.currentUser()(req, res);

    expect(res.statusCode).toEqual(200);
  });

  it('should return userinfo if valid token', async () => {
    const { req, res } = getMockAPIContext({ method: 'GET', headers: { cookie: 'user_session=ACCESS_TOKEN' } });

    await fiefAuth.currentUser()(req, res);

    expect(res.statusCode).toEqual(200);
  });
});
