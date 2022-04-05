/**
 * @jest-environment jsdom
 */
import 'jest-location-mock';

import type { Fief, FiefTokenResponse } from '../client';
import {
  TOKEN_INFO_STORAGE_KEY,
  USERINFO_STORAGE_KEY,
  FiefAuth,
  FiefAuthAuthorizeError,
  IFiefAuthStorage,
  FiefAuthNotAuthenticatedError,
} from './browser';

class MockAuthStorage implements IFiefAuthStorage {
  private storage: Record<string, string>;

  constructor() {
    this.storage = {};
  }

  public getUserinfo(): Record<string, any> | null {
    const value = this.storage[USERINFO_STORAGE_KEY];
    if (!value) {
      return null;
    }
    return JSON.parse(value);
  }

  public setUserinfo(userinfo: Record<string, any>): void {
    this.storage[USERINFO_STORAGE_KEY] = JSON.stringify(userinfo);
  }

  public getTokenInfo(): FiefTokenResponse | null {
    const value = this.storage[TOKEN_INFO_STORAGE_KEY];
    if (!value) {
      return null;
    }
    return JSON.parse(value);
  }

  public setTokenInfo(tokenInfo: FiefTokenResponse): void {
    this.storage[TOKEN_INFO_STORAGE_KEY] = JSON.stringify(tokenInfo);
  }

  public clear(): void {
    this.storage = {};
  }
}

const tokenInfo: FiefTokenResponse = {
  access_token: 'ACCESS_TOKEN',
  expires_in: 3600,
  id_token: 'ID_TOKEN',
  token_type: 'bearer',
};
// @ts-ignore
const fiefMock = jest.fn<Fief, any>(() => ({
  getAuthURL: () => 'https://bretagne.fief.dev/authorize',
  authCallback: () => [tokenInfo, { sub: 'USER_ID' }],
  userinfo: () => ({ sub: 'REFRESHED_USER_ID' }),
}));
const mockAuthStorage = new MockAuthStorage();
const fiefAuth = new FiefAuth(fiefMock(), mockAuthStorage);

beforeEach(() => {
  mockAuthStorage.clear();
});

describe('isAuthenticated', () => {
  it('should return false if no access token in storage', () => {
    expect(fiefAuth.isAuthenticated()).toBeFalsy();
  });

  it('should return true if access token in storage', () => {
    mockAuthStorage.setTokenInfo(tokenInfo);
    expect(fiefAuth.isAuthenticated()).toBeTruthy();
  });
});

describe('getUserinfo', () => {
  it('should return null if no userinfo in storage', () => {
    expect(fiefAuth.getUserinfo()).toBeNull();
  });

  it('should return userinfo object if in storage', () => {
    mockAuthStorage.setUserinfo({ sub: 'USER_ID' });
    expect(fiefAuth.getUserinfo()).toStrictEqual({ sub: 'USER_ID' });
  });
});

describe('getTokenInfo', () => {
  it('should return null if no token info in storage', () => {
    expect(fiefAuth.getTokenInfo()).toBeNull();
  });

  it('should return token info if in storage', () => {
    mockAuthStorage.setTokenInfo(tokenInfo);
    expect(fiefAuth.getTokenInfo()).toStrictEqual(tokenInfo);
  });
});

describe('redirectToLogin', () => {
  it('should redirect to the authorization URL', async () => {
    await fiefAuth.redirectToLogin('https://www.bretagne.duchy/callback');
    expect(window.location).toBeAt('https://bretagne.fief.dev/authorize');
  });
});

describe('authCallback', () => {
  it('should throw an error if error is present in query params', async () => {
    window.location.search = 'error=invalid_request&error_description=An+error+occured';

    expect.assertions(3);
    try {
      await fiefAuth.authCallback('https://www.bretagne.duchy/callback');
    } catch (err) {
      expect(err).toBeInstanceOf(FiefAuthAuthorizeError);
      const authorizeError = err as FiefAuthAuthorizeError;
      expect(authorizeError.error).toBe('invalid_request');
      expect(authorizeError.description).toBe('An error occured');
    }
  });

  it('should throw an error if code is not present in query params', async () => {
    expect.assertions(3);
    try {
      await fiefAuth.authCallback('https://www.bretagne.duchy/callback');
    } catch (err) {
      expect(err).toBeInstanceOf(FiefAuthAuthorizeError);
      const authorizeError = err as FiefAuthAuthorizeError;
      expect(authorizeError.error).toBe('missing_code');
      expect(authorizeError.description).toBeNull();
    }
  });

  it('should retrieve tokens and set them in storage', async () => {
    window.location.search = 'code=CODE';

    await fiefAuth.authCallback('https://www.bretagne.duchy/callback');

    expect(mockAuthStorage.getTokenInfo()).toStrictEqual(tokenInfo);
    expect(mockAuthStorage.getUserinfo()).toStrictEqual({ sub: 'USER_ID' });
  });
});

describe('refreshUserinfo', () => {
  it('should throw an error if no token info', async () => {
    expect.assertions(1);
    try {
      await fiefAuth.refreshUserinfo();
    } catch (err) {
      expect(err).toBeInstanceOf(FiefAuthNotAuthenticatedError);
    }
  });

  it('should return fresh userinfo and set it in storage', async () => {
    mockAuthStorage.setTokenInfo(tokenInfo);

    const refreshedUserinfo = await fiefAuth.refreshUserinfo();
    expect(refreshedUserinfo).toStrictEqual({ sub: 'REFRESHED_USER_ID' });

    const userinfo = await fiefAuth.getUserinfo();
    expect(userinfo).toStrictEqual({ sub: 'REFRESHED_USER_ID' });
  });
});
