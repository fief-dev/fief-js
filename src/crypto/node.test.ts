import { NodeJSCryptoHelper } from './node';

const cryptoHelper = new NodeJSCryptoHelper();

describe('getValidationHash', () => {
  it.each([
    ['foobar', 'w6uP8Tcg6K2QR905Rms8iQ'],
    ['hwQJupLaFEDG4WpDamm7kfeSwr0yY0OdCoF_dSJAwjM', 'iYMQP6yo0iXDaG_of0Y4IQ'],
  ])('should compute the SHA-256 of the value, half it and encode it in Base64', async (value, expected) => {
    const hash = await cryptoHelper.getValidationHash(value);
    expect(hash).toBe(expected);
  });
});

describe('generateCodeVerifier', () => {
  it('should generate an URL-safe random string of length 128', async () => {
    const code = await cryptoHelper.generateCodeVerifier();
    expect(code).toHaveLength(128);

    const allowedCharacters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~'.split('');
    for (let i = 0; i < code.length; i += 1) {
      expect(allowedCharacters).toEqual(expect.arrayContaining([code[i]]));
    }
  });
});

describe('getCodeChallenge', () => {
  it('should return the code verifier with plain method', async () => {
    const challenge = await cryptoHelper.getCodeChallenge('CODE', 'plain');
    expect(challenge).toBe('CODE');
  });

  it('should return te SHA-256 of the value in URL-safe Base64 with S256 method', async () => {
    const challenge = await cryptoHelper.getCodeChallenge('CODE', 'S256');
    expect(challenge).toBe('B6nXtKmiORWmG8ibsDV79Hs0jPQXTrllux34-_oYsLU');
  });

  it('should throw an error if invalid method', async () => {
    expect.assertions(1);

    try {
      // @ts-ignore
      await cryptoHelper.getCodeChallenge('CODE', 'UNKNOWN_METHOD');
    } catch (err) {
      expect(err).toBeInstanceOf(Error);
    }
  });
});
