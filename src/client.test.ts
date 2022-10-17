import fetchMock from 'fetch-mock';

import {
  Fief,
  FiefAccessTokenExpired,
  FiefAccessTokenInvalid,
  FiefAccessTokenMissingPermission,
  FiefAccessTokenMissingScope,
  FiefIdTokenInvalid,
} from './client';
import {
  generateToken, signatureKeyPublic, encryptionKey, userId,
} from '../tests/utils';
import { getCrypto } from './crypto';

const mockFetch = fetchMock.sandbox();
jest.mock('./fetch/index', () => ({ getFetch: () => mockFetch }));

const HOSTNAME = 'https://bretagne.fief.dev';
const fief = new Fief({
  baseURL: HOSTNAME,
  clientId: 'CLIENT_ID',
  clientSecret: 'CLIENT_SECRET',
});

const fiefEncryptionKey = new Fief({
  baseURL: HOSTNAME,
  clientId: 'CLIENT_ID',
  clientSecret: 'CLIENT_SECRET',
  encryptionKey: JSON.stringify(encryptionKey),
});

let accessToken: string;
let signedIdToken: string;
let encryptedIdToken: string;

const cryptoHelper = getCrypto();

beforeAll(async () => {
  accessToken = await generateToken(false);
  signedIdToken = await generateToken(false);
  encryptedIdToken = await generateToken(true);
});

beforeEach(() => {
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
});

describe('getAuthURL', () => {
  it.each(
    [
      [{}, ''],
      [{ state: 'STATE' }, '&state=STATE'],
      [{ scope: ['SCOPE_1', 'SCOPE_2'] }, '&scope=SCOPE_1+SCOPE_2'],
      [{ codeChallenge: 'CODE', codeChallengeMethod: 'S256' as 'S256' }, '&code_challenge=CODE&code_challenge_method=S256'],
      [{ extrasParams: { foo: 'bar' } }, '&foo=bar'],
    ],
  )('should generate URL with params %o', (parameters, expectedParameters) => fief.getAuthURL({
    redirectURI: 'https://www.bretagne.duchy/callback',
    ...parameters,
  }).then((result) => {
    expect(result).toBe(`https://bretagne.fief.dev/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https%3A%2F%2Fwww.bretagne.duchy%2Fcallback${expectedParameters}`);
  }));
});

describe('authCallback', () => {
  it('should validate and decode signed ID token', async () => {
    mockFetch.post('path:/token', {
      status: 200,
      body: {
        access_token: accessToken,
        id_token: signedIdToken,
        token_type: 'bearer',
      },
    });

    const [tokenResponse, userinfo] = await fief.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    expect(tokenResponse.access_token).toBe(accessToken);
    expect(tokenResponse.id_token).toBe(signedIdToken);

    expect(userinfo.sub).toBe(userId);
  });

  it('should validate and decode encrypted ID token', async () => {
    mockFetch.post('path:/token', {
      status: 200,
      body: {
        access_token: accessToken,
        id_token: encryptedIdToken,
        token_type: 'bearer',
      },
    });

    const [tokenResponse, userinfo] = await fiefEncryptionKey.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    expect(tokenResponse.access_token).toBe(accessToken);
    expect(tokenResponse.id_token).toBe(encryptedIdToken);

    expect(userinfo.sub).toBe(userId);
  });

  it('should reject invalid ID token', async () => {
    mockFetch.post('path:/token', {
      status: 200,
      body: {
        access_token: accessToken,
        id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
        token_type: 'bearer',
      },
    });

    expect.assertions(1);
    try {
      await fief.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    } catch (err) {
      expect(err).toBeInstanceOf(FiefIdTokenInvalid);
    }
  });

  it('should reject encrypted ID token without encryption key', async () => {
    mockFetch.post('path:/token', {
      status: 200,
      body: {
        access_token: accessToken,
        id_token: encryptedIdToken,
        token_type: 'bearer',
      },
    });

    expect.assertions(1);
    try {
      await fief.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    } catch (err) {
      expect(err).toBeInstanceOf(FiefIdTokenInvalid);
    }
  });

  it('should validate correct at_hash and c_hash claims', async () => {
    const codeValidationHash = await cryptoHelper.getValidationHash('CODE');
    const accessTokenValidationHash = await cryptoHelper.getValidationHash('ACCESS_TOKEN');

    const idToken = await generateToken(
      false,
      { c_hash: codeValidationHash, at_hash: accessTokenValidationHash },
    );

    mockFetch.post('path:/token', {
      status: 200,
      body: {
        access_token: 'ACCESS_TOKEN',
        id_token: idToken,
        token_type: 'bearer',
      },
    });

    const [tokenResponse, userinfo] = await fief.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    expect(tokenResponse.access_token).toBe('ACCESS_TOKEN');
    expect(tokenResponse.id_token).toBe(idToken);

    expect(userinfo.sub).toBe(userId);
  });

  it('should reject invalid at_hash and c_hash claims', async () => {
    const codeValidationHash = await cryptoHelper.getValidationHash('INVALID_CODE');
    const accessTokenValidationHash = await cryptoHelper.getValidationHash('INVALID_ACCESS_TOKEN');

    const idToken = await generateToken(
      false,
      { c_hash: codeValidationHash, at_hash: accessTokenValidationHash },
    );

    mockFetch.post('path:/token', {
      status: 200,
      body: {
        access_token: 'ACCESS_TOKEN',
        id_token: idToken,
        token_type: 'bearer',
      },
    });

    expect.assertions(1);
    try {
      await fief.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    } catch (err) {
      expect(err).toBeInstanceOf(FiefIdTokenInvalid);
    }
  });
});

describe('authRefreshToken', () => {
  it('should validate and decode signed ID token', async () => {
    mockFetch.post('path:/token', {
      status: 200,
      body: {
        access_token: accessToken,
        id_token: signedIdToken,
        token_type: 'bearer',
      },
    });

    const [tokenResponse, userinfo] = await fief.authRefreshToken('REFRESH_TOKEN', ['openid', 'offline_access']);
    expect(tokenResponse.access_token).toBe(accessToken);
    expect(tokenResponse.id_token).toBe(signedIdToken);

    expect(userinfo.sub).toBe(userId);
  });
});

describe('validateAccessToken', () => {
  it('should reject invalid signature', async () => {
    expect.assertions(1);
    try {
      await fief.validateAccessToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
    } catch (err) {
      expect(err).toBeInstanceOf(FiefAccessTokenInvalid);
    }
  });

  it('should reject invalid claims', async () => {
    expect.assertions(1);
    try {
      await fief.validateAccessToken('eyJhbGciOiJSUzI1NiJ9.e30.RmKxjgPljzJL_-Yp9oBJIvNejvES_pnTeZBDvptYcdWm4Ze9D6FlM8RFJ5-ZJ3O-HXlWylVXiGAE_wdSGXehSaENUN3Mj91j5OfiXGrtBGSiEiCtC9HYKCi6xf6xmcEPoTbtBVi38a9OARoJlpTJ5T4BbmqIUR8R06sqo3zTkwk48wPmYtk_OPgMv4c8tNyHF17dRe1JM_ix-m7V1Nv_2DHLMRgMXdsWkl0RCcAFQwqCTXU4UxWSoXp6CB0-Ybkq-P5KyXIXy0b15qG8jfgCrFHqFhN3hpyvL4Zza_EkXJaCkB5v-oztlHS6gTGb3QgFqppW3JM6TJnDKslGRPDsjg');
    } catch (err) {
      expect(err).toBeInstanceOf(FiefAccessTokenInvalid);
    }
  });

  it('should reject expired access token', async () => {
    const newAccessToken = await generateToken(false, { scope: 'openid', permissions: [] }, 0);

    expect.assertions(1);
    try {
      await fief.validateAccessToken(newAccessToken);
    } catch (err) {
      expect(err).toBeInstanceOf(FiefAccessTokenExpired);
    }
  });

  it('should reject if missing required scope', async () => {
    const newAccessToken = await generateToken(false, { scope: 'openid', permissions: [] });

    expect.assertions(1);
    try {
      await fief.validateAccessToken(newAccessToken, ['REQUIRED']);
    } catch (err) {
      expect(err).toBeInstanceOf(FiefAccessTokenMissingScope);
    }
  });

  it('should validate token with right scope', async () => {
    const newAccessToken = await generateToken(false, { scope: 'openid offline_access', permissions: [] });

    const info = await fief.validateAccessToken(newAccessToken, ['openid', 'offline_access']);
    expect(info).toStrictEqual({
      id: userId,
      scope: ['openid', 'offline_access'],
      permissions: [],
      access_token: newAccessToken,
    });
  });

  it('should reject if missing required permission', async () => {
    const newAccessToken = await generateToken(false, { scope: 'openid', permissions: ['castles:read'] });

    expect.assertions(1);
    try {
      await fief.validateAccessToken(newAccessToken, undefined, ['castles:create']);
    } catch (err) {
      expect(err).toBeInstanceOf(FiefAccessTokenMissingPermission);
    }
  });

  it('should validate token with right permissions', async () => {
    const newAccessToken = await generateToken(false, { scope: 'openid', permissions: ['castles:read', 'castles:create'] });

    const info = await fief.validateAccessToken(newAccessToken, undefined, ['castles:create']);
    expect(info).toStrictEqual({
      id: userId,
      scope: ['openid'],
      permissions: ['castles:read', 'castles:create'],
      access_token: newAccessToken,
    });
  });
});

describe('userinfo', () => {
  it('should return data from userinfo endpoint', async () => {
    mockFetch.get('path:/userinfo', { status: 200, body: { sub: userId } });

    const userinfo = await fief.userinfo('ACCESS_TOKEN');
    expect(userinfo).toStrictEqual({ sub: userId });
  });
});

describe('updateProfile', () => {
  it('should return data from userinfo endpoint', async () => {
    mockFetch.patch('path:/api/profile', { status: 200, body: { sub: userId } });

    const userinfo = await fief.updateProfile('ACCESS_TOKEN', { email: 'anne@bretagne.duchy' });
    expect(userinfo).toStrictEqual({ sub: userId });
  });
});

describe('getLogoutURL', () => {
  it('should generate URL with redirect_uri parameter', async () => {
    const logoutURL = await fief.getLogoutURL({ redirectURI: 'https://www.bretagne.duchy' });
    expect(logoutURL).toBe('https://bretagne.fief.dev/logout?redirect_uri=https%3A%2F%2Fwww.bretagne.duchy');
  });
});
