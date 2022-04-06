import { getValidationHash } from './crypto';

describe('getValidationHash', () => {
  it('should compute the SHA-256 of the value, half it and encode it in Base64', () => {
    const value = getValidationHash('foobar');
    expect(value).toBe('w6uP8Tcg6K2QR905Rms8iQ');
  });
});
