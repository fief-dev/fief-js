import express, { Express } from 'express';
import session from 'express-session';
import fetchMock from 'fetch-mock';
import request from 'supertest';

import { generateToken, signatureKeyPublic, userId } from '../../tests/utils';
import { Fief, FiefACR, FiefUserInfo } from '../client';
import { authorizationSchemeGetter, IUserInfoCache } from '../server';
import { createMiddleware } from './index';

const mockFetch = fetchMock.sandbox();
jest.mock('../fetch/index', () => ({ getFetch: () => mockFetch }));

const HOSTNAME = 'https://bretagne.fief.dev';
const fief = new Fief({
  baseURL: HOSTNAME,
  clientId: 'CLIENT_ID',
  clientSecret: 'CLIENT_SECRET',
});

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

const fiefAuthMiddleware = createMiddleware({
  client: fief,
  tokenGetter: authorizationSchemeGetter(),
  userInfoCache,
});

const testApp = (): Express => {
  const app = express();
  app.use(session({ secret: 'SECRET', resave: false, saveUninitialized: false }));

  app.get('/authenticated', fiefAuthMiddleware(), (req, res) => {
    res.json(req.accessTokenInfo);
  });

  app.get('/authenticated-optional', fiefAuthMiddleware({ optional: true }), (req, res) => {
    res.json(req.accessTokenInfo || {});
  });

  app.get('/authenticated-scope', fiefAuthMiddleware({ scope: ['required_scope'] }), (req, res) => {
    res.json(req.accessTokenInfo);
  });

  app.get('/authenticated-acr', fiefAuthMiddleware({ acr: FiefACR.LEVEL_ONE }), (req, res) => {
    res.json(req.accessTokenInfo);
  });

  app.get('/authenticated-permission', fiefAuthMiddleware({ permissions: ['castles:create'] }), (req, res) => {
    res.json(req.accessTokenInfo);
  });

  app.get('/current-user', fiefAuthMiddleware(), (req, res) => {
    res.json(req.user);
  });

  app.get('/current-user-refresh', fiefAuthMiddleware({ refresh: true }), (req, res) => {
    res.json(req.user);
  });

  return app;
};

beforeEach(async () => {
  await userInfoCache.clear();
  mockFetch.reset();

  mockFetch.get('path:/.well-known/openid-configuration', {
    status: 200,
    body: {
      authorization_endpoint: `${HOSTNAME}/authorize`,
      token_endpoint: `${HOSTNAME}/token`,
      userinfo_endpoint: `${HOSTNAME}/userinfo`,
      jwks_uri: `${HOSTNAME}/.well-known/jwks.json`,
    },
  });

  mockFetch.get('path:/.well-known/jwks.json', {
    status: 200,
    body: {
      keys: [signatureKeyPublic],
    },
  });

  mockFetch.get('path:/userinfo', { status: 200, body: { sub: userId } });
});

describe('fiefAuth', () => {
  it('should return 401 if no Authorization header', async () => {
    const response = await request(testApp())
      .get('/authenticated')
      ;
    expect(response.statusCode).toEqual(401);
  });

  it('should return 401 if invalid Authorization header', async () => {
    const response = await request(testApp())
      .get('/authenticated')
      .set('Authorization', 'TOKEN')
      ;
    expect(response.statusCode).toEqual(401);
  });

  it('should return 401 if expired token', async () => {
    const accessToken = await generateToken(false, { scope: 'openid', permissions: [] }, 0);
    const response = await request(testApp())
      .get('/authenticated')
      .set('Authorization', `Bearer ${accessToken}`)
      ;
    expect(response.statusCode).toEqual(401);
  });

  it('should set accessTokenInfo in Request object if valid token', async () => {
    const accessToken = await generateToken(false, { scope: 'openid', acr: FiefACR.LEVEL_ZERO, permissions: [] });
    const response = await request(testApp())
      .get('/authenticated')
      .set('Authorization', `Bearer ${accessToken}`)
      ;
    expect(response.statusCode).toEqual(200);
    expect(response.body).toEqual({
      id: userId,
      scope: ['openid'],
      acr: FiefACR.LEVEL_ZERO,
      permissions: [],
      access_token: accessToken,
    });
  });

  describe('optional', () => {
    it('should not throw 401 if no token', async () => {
      const response = await request(testApp())
        .get('/authenticated-optional')
        ;
      expect(response.statusCode).toEqual(200);
      expect(response.body).toEqual({});
    });

    it('should not throw 401 if expired token', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: [] }, 0);

      const response = await request(testApp())
        .get('/authenticated-optional')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(response.statusCode).toEqual(200);
      expect(response.body).toEqual({});
    });

    it('should set accessTokenInfo in Request object if valid token', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', acr: FiefACR.LEVEL_ZERO, permissions: [] });
      const response = await request(testApp())
        .get('/authenticated-optional')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(response.statusCode).toEqual(200);
      expect(response.body).toEqual({
        id: userId,
        scope: ['openid'],
        acr: FiefACR.LEVEL_ZERO,
        permissions: [],
        access_token: accessToken,
      });
    });
  });

  describe('scope', () => {
    it('should throw 403 if missing scope', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', acr: FiefACR.LEVEL_ZERO, permissions: [] });
      const response = await request(testApp())
        .get('/authenticated-scope')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(response.statusCode).toEqual(403);
    });

    it('should set accessTokenInfo in Request object if valid scope', async () => {
      const accessToken = await generateToken(false, { scope: 'openid required_scope', acr: FiefACR.LEVEL_ZERO, permissions: [] });
      const response = await request(testApp())
        .get('/authenticated-scope')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(response.statusCode).toEqual(200);
      expect(response.body).toEqual({
        id: userId,
        scope: ['openid', 'required_scope'],
        acr: FiefACR.LEVEL_ZERO,
        permissions: [],
        access_token: accessToken,
      });
    });
  });

  describe('acr', () => {
    it('should throw 403 if invalid ACR', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', acr: FiefACR.LEVEL_ZERO, permissions: [] });
      const response = await request(testApp())
        .get('/authenticated-acr')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(response.statusCode).toEqual(403);
    });

    it('should set accessTokenInfo in Request object if valid ACR', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', acr: FiefACR.LEVEL_ONE, permissions: [] });
      const response = await request(testApp())
        .get('/authenticated-acr')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(response.statusCode).toEqual(200);
      expect(response.body).toEqual({
        id: userId,
        scope: ['openid'],
        acr: FiefACR.LEVEL_ONE,
        permissions: [],
        access_token: accessToken,
      });
    });
  });

  describe('permission', () => {
    it('should throw 403 if missing permission', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', acr: FiefACR.LEVEL_ZERO, permissions: ['castles:read'] });
      const response = await request(testApp())
        .get('/authenticated-permission')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(response.statusCode).toEqual(403);
    });

    it('should set accessTokenInfo in Request object if valid permission', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', acr: FiefACR.LEVEL_ZERO, permissions: ['castles:read', 'castles:create'] });
      const response = await request(testApp())
        .get('/authenticated-permission')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(response.statusCode).toEqual(200);
      expect(response.body).toEqual({
        id: userId,
        scope: ['openid'],
        acr: FiefACR.LEVEL_ZERO,
        permissions: ['castles:read', 'castles:create'],
        access_token: accessToken,
      });
    });
  });

  describe('user', () => {
    it('should get userinfo from API and set it in storage', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', acr: FiefACR.LEVEL_ZERO, permissions: [] });
      const app = testApp();

      const responseFirst = await request(app)
        .get('/current-user')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(responseFirst.statusCode).toEqual(200);
      expect(responseFirst.body).toEqual({ sub: userId });

      const responseSecond = await request(app)
        .get('/current-user')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(responseSecond.statusCode).toEqual(200);
      expect(responseSecond.body).toEqual({ sub: userId });

      expect(mockFetch.calls('path:/userinfo').length).toEqual(1);
    });

    it('should always get userinfo from API if refresh', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', acr: FiefACR.LEVEL_ZERO, permissions: [] });
      const app = testApp();

      const responseFirst = await request(app)
        .get('/current-user-refresh')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(responseFirst.statusCode).toEqual(200);
      expect(responseFirst.body).toEqual({ sub: userId });

      const responseSecond = await request(app)
        .get('/current-user-refresh')
        .set('Authorization', `Bearer ${accessToken}`)
        ;
      expect(responseSecond.statusCode).toEqual(200);
      expect(responseSecond.body).toEqual({ sub: userId });

      expect(mockFetch.calls('path:/userinfo').length).toEqual(2);
    });
  });
});
