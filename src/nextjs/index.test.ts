/* eslint-disable class-methods-use-this */
import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';
import { IncomingMessage, OutgoingMessage } from 'http';
import httpMocks from 'node-mocks-http';
import { GetServerSidePropsContext, NextApiRequest, NextApiResponse } from 'next';

import { Fief, FiefUserInfo } from '../client';
import { generateToken, signatureKeyPublic, userId } from '../../tests/utils';
import { FiefAuth } from './index';
import { AuthenticateRequestResult, authorizationBearerGetter, IUserInfoCache } from '../server';

const axiosMock = new MockAdapter(axios);

const HOSTNAME = 'https://bretagne.fief.dev';
const fief = new Fief({
  baseURL: HOSTNAME,
  clientId: 'CLIENT_ID',
  clientSecret: 'CLIENT_SECRET',
});

class UserInfoCache implements IUserInfoCache<IncomingMessage, OutgoingMessage> {
  private storage: Record<string, any>;

  constructor() {
    this.storage = {};
  }

  async get(
    id: string,
    _req: IncomingMessage,
    _res: OutgoingMessage,
  ): Promise<FiefUserInfo | null> {
    const userinfo = this.storage[id];
    if (userinfo) {
      return userinfo;
    }
    return null;
  }

  async set(
    id: string,
    userinfo: FiefUserInfo,
    _req: IncomingMessage,
    _res: OutgoingMessage,
  ): Promise<void> {
    this.storage[id] = userinfo;
  }

  async remove(id: string, _req: IncomingMessage, _res: OutgoingMessage): Promise<void> {
    this.storage[id] = undefined;
  }

  async clear(_req: IncomingMessage, _res: OutgoingMessage): Promise<void> {
    this.storage = {};
  }
}

const userInfoCache = new UserInfoCache();

const fiefAuth = new FiefAuth({
  client: fief,
  tokenGetter: authorizationBearerGetter,
  userInfoCache,
  redirectURI: 'http://localhost:3000/callback',
});

let userinfoMock: MockAdapter;

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

beforeEach(async () => {
  await userInfoCache.clear(jest.fn() as any, jest.fn() as any);
  userinfoMock.resetHistory();
});

describe('withAuth', () => {
  it('should return a redirection response if no Authorization header', async () => {
    const context = getMockContext({ method: 'GET' });
    const result = await fiefAuth.withAuth(getMockGetServerSideProps())(context);

    // @ts-ignore
    expect(result.redirect.destination).toMatch(`${HOSTNAME}/authorize`);
    // @ts-ignore
    expect(result.redirect.permanent).toEqual(false);
  });

  it('should return a redirection response if invalid Authorization header', async () => {
    const context = getMockContext({ method: 'GET', headers: { authorization: 'TOKEN' } });
    const result = await fiefAuth.withAuth(getMockGetServerSideProps())(context);

    // @ts-ignore
    expect(result.redirect.destination).toMatch(`${HOSTNAME}/authorize`);
    // @ts-ignore
    expect(result.redirect.permanent).toEqual(false);
  });

  it('should return a redirection response if expired token', async () => {
    const accessToken = await generateToken(false, { scope: 'openid', permissions: [] }, 0);
    const context = getMockContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
    const result = await fiefAuth.withAuth(getMockGetServerSideProps())(context);

    // @ts-ignore
    expect(result.redirect.destination).toMatch(`${HOSTNAME}/authorize`);
    // @ts-ignore
    expect(result.redirect.permanent).toEqual(false);
  });

  it('should set accessTokenInfo in props if valid token', async () => {
    const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
    const context = getMockContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
    const result = await fiefAuth.withAuth(getMockGetServerSideProps())(context);

    // @ts-ignore
    expect(result.props.accessTokenInfo).toEqual({
      id: userId,
      scope: ['openid'],
      permissions: [],
      access_token: accessToken,
    });
  });

  it('should set accessTokenInfo in props if valid token with async getServerSideProps', async () => {
    const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
    const context = getMockContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
    const result = await fiefAuth.withAuth(getMockGetServerSidePropsPromise())(context);

    // @ts-ignore
    expect(result.props.accessTokenInfo).toEqual({
      id: userId,
      scope: ['openid'],
      permissions: [],
      access_token: accessToken,
    });
  });

  it('should return raw response with getServerSideProps not returning props', async () => {
    const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
    const context = getMockContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
    const result = await fiefAuth.withAuth(getMockGetServerSidePropsRedirectResult())(context);

    // @ts-ignore
    expect(result.props.accessTokenInfo).toEqual({ redirect: {} });
  });

  describe('scope', () => {
    it('should set forbidden in props if missing scope', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
      const context = getMockContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      const result = await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { scope: ['openid', 'required_scope'] },
      )(context);

      // @ts-ignore
      expect(result.props.forbidden).toEqual(true);
    });

    it('should set accessTokenInfo in props if valid scope', async () => {
      const accessToken = await generateToken(false, { scope: 'openid required_scope', permissions: [] });
      const context = getMockContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      const result = await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { scope: ['openid', 'required_scope'] },
      )(context);

      // @ts-ignore
      expect(result.props.accessTokenInfo).toEqual({
        id: userId,
        scope: ['openid', 'required_scope'],
        permissions: [],
        access_token: accessToken,
      });
    });
  });

  describe('permission', () => {
    it('should set forbidden in props if missing permission', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: ['castles:read'] });
      const context = getMockContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      const result = await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { permissions: ['castles:create'] },
      )(context);

      // @ts-ignore
      expect(result.props.forbidden).toEqual(true);
    });

    it('should set accessTokenInfo in props if valid permission', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: ['castles:read', 'castles:create'] });
      const context = getMockContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      const result = await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { permissions: ['castles:create'] },
      )(context);

      // @ts-ignore
      expect(result.props.accessTokenInfo).toEqual({
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
      const context = getMockContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      const firstResult = await fiefAuth.withAuth(getMockGetServerSideProps())(context);

      // @ts-ignore
      expect(firstResult.props.user).toEqual({ sub: userId });

      const secondResult = await fiefAuth.withAuth(getMockGetServerSideProps())(context);
      // @ts-ignore
      expect(secondResult.props.user).toEqual({ sub: userId });

      expect(userinfoMock.history.get.length).toEqual(1);
    });

    it('should always get userinfo from API if refresh', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
      const context = getMockContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      const firstResult = await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { refresh: true },
      )(context);

      // @ts-ignore
      expect(firstResult.props.user).toEqual({ sub: userId });

      const secondResult = await fiefAuth.withAuth(
        getMockGetServerSideProps(),
        { refresh: true },
      )(context);
      // @ts-ignore
      expect(secondResult.props.user).toEqual({ sub: userId });

      expect(userinfoMock.history.get.length).toEqual(2);
    });
  });
});

describe('authenticated', () => {
  it('should return 401 if no Authorization header', async () => {
    const { req, res } = getMockAPIContext({ method: 'GET' });
    await fiefAuth.authenticated(getMockNextAPIHandler())(req, res);

    expect(res.statusCode).toEqual(401);
  });

  it('should return 401 if invalid Authorization header', async () => {
    const { req, res } = getMockAPIContext({ method: 'GET', headers: { authorization: 'TOKEN' } });
    await fiefAuth.authenticated(getMockNextAPIHandler())(req, res);

    expect(res.statusCode).toEqual(401);
  });

  it('should return 401 if expired token', async () => {
    const accessToken = await generateToken(false, { scope: 'openid', permissions: [] }, 0);
    const { req, res } = getMockAPIContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
    await fiefAuth.authenticated(getMockNextAPIHandler())(req, res);

    expect(res.statusCode).toEqual(401);
  });

  it('should set accessTokenInfo in Request object if valid token', async () => {
    const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
    const { req, res } = getMockAPIContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
    await fiefAuth.authenticated(getMockNextAPIHandler())(req, res);

    expect(req.accessTokenInfo).toEqual({
      id: userId,
      scope: ['openid'],
      permissions: [],
      access_token: accessToken,
    });
  });

  describe('optional', () => {
    it('should not throw 401 if no token', async () => {
      const { req, res } = getMockAPIContext({ method: 'GET' });
      await fiefAuth.authenticated(getMockNextAPIHandler(), { optional: true })(req, res);

      expect(res.statusCode).toEqual(200);
    });

    it('should set accessTokenInfo in Request object if valid token', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
      const { req, res } = getMockAPIContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      await fiefAuth.authenticated(getMockNextAPIHandler(), { optional: true })(req, res);

      expect(req.accessTokenInfo).toEqual({
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
      const { req, res } = getMockAPIContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      await fiefAuth.authenticated(getMockNextAPIHandler(), { scope: ['required_scope'] })(req, res);

      expect(res.statusCode).toEqual(403);
    });

    it('should set accessTokenInfo in Request object if valid scope', async () => {
      const accessToken = await generateToken(false, { scope: 'openid required_scope', permissions: [] });
      const { req, res } = getMockAPIContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      await fiefAuth.authenticated(getMockNextAPIHandler(), { scope: ['required_scope'] })(req, res);

      expect(req.accessTokenInfo).toEqual({
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
      const { req, res } = getMockAPIContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      await fiefAuth.authenticated(getMockNextAPIHandler(), { permissions: ['castles:create'] })(req, res);

      expect(res.statusCode).toEqual(403);
    });

    it('should set accessTokenInfo in Request object if valid permission', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: ['castles:read', 'castles:create'] });
      const { req, res } = getMockAPIContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      await fiefAuth.authenticated(getMockNextAPIHandler(), { permissions: ['castles:create'] })(req, res);

      expect(req.accessTokenInfo).toEqual({
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
      const { req: firstReq, res: firstRes } = getMockAPIContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      await fiefAuth.authenticated(getMockNextAPIHandler())(firstReq, firstRes);
      expect(firstReq.user).toEqual({ sub: userId });

      const { req: secondReq, res: secondRes } = getMockAPIContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      await fiefAuth.authenticated(getMockNextAPIHandler())(secondReq, secondRes);
      expect(secondReq.user).toEqual({ sub: userId });

      expect(userinfoMock.history.get.length).toEqual(1);
    });

    it('should always get userinfo from API if refresh', async () => {
      const accessToken = await generateToken(false, { scope: 'openid', permissions: [] });
      const { req: firstReq, res: firstRes } = getMockAPIContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      await fiefAuth.authenticated(
        getMockNextAPIHandler(),
        { refresh: true },
      )(firstReq, firstRes);
      expect(firstReq.user).toEqual({ sub: userId });

      const { req: secondReq, res: secondRes } = getMockAPIContext({ method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
      await fiefAuth.authenticated(
        getMockNextAPIHandler(),
        { refresh: true },
      )(secondReq, secondRes);
      expect(secondReq.user).toEqual({ sub: userId });

      expect(userinfoMock.history.get.length).toEqual(2);
    });
  });
});
