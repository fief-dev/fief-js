import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';
import express, { Express, Request } from 'express';
import session from 'express-session';
import request from 'supertest';

import { Fief, FiefUserInfo } from '../client';
import { generateToken, signatureKeyPublic, userId } from '../../tests/utils';
import { authorizationBearerGetter, fiefAuth } from './index';

const axiosMock = new MockAdapter(axios);

const HOSTNAME = 'https://bretagne.fief.dev';
const fief = new Fief({
  baseURL: HOSTNAME,
  clientId: 'CLIENT_ID',
  clientSecret: 'CLIENT_SECRET',
});

const getUserInfoCache = (id: string, req: Request): FiefUserInfo | null => {
  // @ts-ignore
  const userinfo = req.session[`userinfo-${id}`];
  if (userinfo) {
    return userinfo;
  }
  return null;
};

const setUserInfoCache = (id: string, userinfo: FiefUserInfo, req: Request): void => {
  // @ts-ignore
  req.session[`userinfo-${id}`] = userinfo;
};

const fiefAuthMiddleware = fiefAuth({
  fief,
  tokenGetter: authorizationBearerGetter,
  getUserInfoCache,
  setUserInfoCache,
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

let userinfoMock: MockAdapter;

beforeAll(async () => {
  axiosMock.onGet('/.well-known/openid-configuration').reply(
    200,
    {
      authorization_endpoint: `${HOSTNAME}/authorize`,
      token_endpoint: `${HOSTNAME}/token`,
      userinfo_endpoint: `${HOSTNAME}/userinfo`,
      jwks_uri: `${HOSTNAME}/.well-known/jwks.json`,
    },
  );

  axiosMock.onGet('/.well-known/jwks.json').reply(
    200,
    {
      keys: [signatureKeyPublic],
    },
  );

  userinfoMock = axiosMock.onGet('/userinfo').reply(200, { sub: userId });
});

beforeEach(() => {
  userinfoMock.resetHistory();
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
    const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
    const response = await request(testApp())
      .get('/authenticated')
      .set('Authorization', `Bearer ${accessToken}`)
    ;
    expect(response.statusCode).toEqual(200);
    expect(response.body).toEqual({
      id: userId,
      scope: ['openid'],
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

    it('should set accessTokenInfo in Request object if valid token', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
      const response = await request(testApp())
        .get('/authenticated-optional')
        .set('Authorization', `Bearer ${accessToken}`)
      ;
      expect(response.statusCode).toEqual(200);
      expect(response.body).toEqual({
        id: userId,
        scope: ['openid'],
        permissions: [],
        access_token: accessToken,
      });
    });
  });

  describe('scope', () => {
    it('should throw 403 if missing scope', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
      const response = await request(testApp())
        .get('/authenticated-scope')
        .set('Authorization', `Bearer ${accessToken}`)
      ;
      expect(response.statusCode).toEqual(403);
    });

    it('should set accessTokenInfo in Request object if valid scope', async () => {
      const accessToken = await generateToken(false, { scope: 'openid required_scope', permissions: [] });
      const response = await request(testApp())
        .get('/authenticated-scope')
        .set('Authorization', `Bearer ${accessToken}`)
      ;
      expect(response.statusCode).toEqual(200);
      expect(response.body).toEqual({
        id: userId,
        scope: ['openid', 'required_scope'],
        permissions: [],
        access_token: accessToken,
      });
    });
  });

  describe('permission', () => {
    it('should throw 403 if missing permission', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: ['castles:read'] });
      const response = await request(testApp())
        .get('/authenticated-permission')
        .set('Authorization', `Bearer ${accessToken}`)
      ;
      expect(response.statusCode).toEqual(403);
    });

    it('should set accessTokenInfo in Request object if valid permission', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: ['castles:read', 'castles:create'] });
      const response = await request(testApp())
        .get('/authenticated-permission')
        .set('Authorization', `Bearer ${accessToken}`)
      ;
      expect(response.statusCode).toEqual(200);
      expect(response.body).toEqual({
        id: userId,
        scope: ['openid'],
        permissions: ['castles:read', 'castles:create'],
        access_token: accessToken,
      });
    });
  });

  describe('user', () => {
    it('should get userinfo from API and set it in storage', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
      const app = testApp();

      const responseFirst = await request(app)
        .get('/current-user')
        .set('Authorization', `Bearer ${accessToken}`)
      ;
      expect(responseFirst.statusCode).toEqual(200);
      expect(responseFirst.body).toEqual({ sub: userId });

      const sessionCookie = responseFirst.headers['set-cookie'][0].split(';')[0];

      const responseSecond = await request(app)
        .get('/current-user')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('Cookie', sessionCookie)
      ;
      expect(responseSecond.statusCode).toEqual(200);
      expect(responseSecond.body).toEqual({ sub: userId });

      expect(userinfoMock.history.get.length).toEqual(1);
    });

    it('should always get userinfo from API if refresh', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
      const app = testApp();

      const responseFirst = await request(app)
        .get('/current-user-refresh')
        .set('Authorization', `Bearer ${accessToken}`)
      ;
      expect(responseFirst.statusCode).toEqual(200);
      expect(responseFirst.body).toEqual({ sub: userId });

      const sessionCookie = responseFirst.headers['set-cookie'][0].split(';')[0];

      const responseSecond = await request(app)
        .get('/current-user-refresh')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('Cookie', sessionCookie)
      ;
      expect(responseSecond.statusCode).toEqual(200);
      expect(responseSecond.body).toEqual({ sub: userId });

      expect(userinfoMock.history.get.length).toEqual(2);
    });
  });
});
