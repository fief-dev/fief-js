import { getValidationHash } from './crypto';

describe('getValidationHash', () => {
  it.each([
    ['foobar', 'w6uP8Tcg6K2QR905Rms8iQ'],
    ['hwQJupLaFEDG4WpDamm7kfeSwr0yY0OdCoF_dSJAwjM', 'iYMQP6yo0iXDaG_of0Y4IQ'],
  ])('should compute the SHA-256 of the value, half it and encode it in Base64', async (value, expected) => {
    const hash = await getValidationHash(value);
    expect(hash).toBe(expected);
  });
});
