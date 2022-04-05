import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';

import { Fief, FiefIdTokenInvalid } from './client';
import { generateToken, signatureKeyPublic, encryptionKey, userId } from '../tests/utils';
import { getValidationHash } from './crypto';

var axiosMock = new MockAdapter(axios);

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

beforeAll(async () => {
  accessToken = await generateToken(false);
  signedIdToken = await generateToken(false);
  encryptedIdToken = await generateToken(true);

  axiosMock.onGet('/.well-known/openid-configuration').reply(
    200,
    {
      authorization_endpoint: `${HOSTNAME}/auth/authorize`,
      token_endpoint: `${HOSTNAME}/auth/token`,
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
});

describe('getAuthURL', () => {
  it.each(
    [
      [{}, ''],
      [{ state: 'STATE' }, '&state=STATE'],
      [{ scope: ['SCOPE_1', 'SCOPE_2'] }, '&scope=SCOPE_1+SCOPE_2'],
      [{ extrasParams: { foo: 'bar' } }, '&foo=bar'],
    ],
  )('should generate URL with params %o', (parameters, expected_parameters) => {
    return fief.getAuthURL({
      redirectURI: 'https://www.bretagne.duchy/callback',
      ...parameters,
    }).then((result) => {
      expect(result).toBe(`https://bretagne.fief.dev/auth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https%3A%2F%2Fwww.bretagne.duchy%2Fcallback${expected_parameters}`)
    });
  });
});

describe('authCallback', () => {
  it('should validate and decode signed ID token', async () => {
    axiosMock.onPost('/auth/token').reply(
      200,
      {
        "access_token": accessToken,
        "id_token": signedIdToken,
        "token_type": 'bearer',
      },
    );

    const [tokenResponse, userinfo] = await fief.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    expect(tokenResponse.access_token).toBe(accessToken);
    expect(tokenResponse.id_token).toBe(signedIdToken);

    expect(userinfo["sub"]).toBe(userId);
  });

  it('should validate and decode encrypted ID token', async () => {
    axiosMock.onPost('/auth/token').reply(
      200,
      {
        "access_token": accessToken,
        "id_token": encryptedIdToken,
        "token_type": 'bearer',
      },
    );

    const [tokenResponse, userinfo] = await fiefEncryptionKey.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    expect(tokenResponse.access_token).toBe(accessToken);
    expect(tokenResponse.id_token).toBe(encryptedIdToken);

    expect(userinfo["sub"]).toBe(userId);
  });

  it('should reject invalid ID token', async () => {
    axiosMock.onPost('/auth/token').reply(
      200,
      {
        "access_token": accessToken,
        "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "token_type": 'bearer',
      },
    );

    expect.assertions(1);
    try {
      await fief.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    } catch (err) {
      expect(err).toBeInstanceOf(FiefIdTokenInvalid);
    }
  });

  it('should reject encrypted ID token without encryption key', async () => {
    axiosMock.onPost('/auth/token').reply(
      200,
      {
        "access_token": accessToken,
        "id_token": encryptedIdToken,
        "token_type": 'bearer',
      },
    );

    expect.assertions(1);
    try {
      await fief.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    } catch (err) {
      expect(err).toBeInstanceOf(FiefIdTokenInvalid);
    }
  });

  it('should validate correct at_hash and c_hash claims', async () => {
    const codeValidationHash = await getValidationHash('CODE');
    const accessTokenValidationHash = await getValidationHash('ACCESS_TOKEN');

    const idToken = await generateToken(false, { c_hash: codeValidationHash, at_hash: accessTokenValidationHash });

    axiosMock.onPost('/auth/token').reply(
      200,
      {
        "access_token": 'ACCESS_TOKEN',
        "id_token": idToken,
        "token_type": 'bearer',
      },
    );

    const [tokenResponse, userinfo] = await fief.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    expect(tokenResponse.access_token).toBe('ACCESS_TOKEN');
    expect(tokenResponse.id_token).toBe(idToken);

    expect(userinfo["sub"]).toBe(userId);
  });

  it('should reject invalid at_hash and c_hash claims', async () => {
    const codeValidationHash = await getValidationHash('INVALID_CODE');
    const accessTokenValidationHash = await getValidationHash('INVALID_ACCESS_TOKEN');

    const idToken = await generateToken(false, { c_hash: codeValidationHash, at_hash: accessTokenValidationHash });

    axiosMock.onPost('/auth/token').reply(
      200,
      {
        "access_token": 'ACCESS_TOKEN',
        "id_token": idToken,
        "token_type": 'bearer',
      },
    );

    expect.assertions(1);
    try {
      await fief.authCallback('CODE', 'https://www.bretagne.duchy/callback');
    } catch (err) {
      expect(err).toBeInstanceOf(FiefIdTokenInvalid);
    }
  });
});
