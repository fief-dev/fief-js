import httpMocks from 'node-mocks-http';

import { authorizationSchemeGetter, cookieGetter } from './server';

describe('authorizationSchemeGetter', () => {
  const tokenGetter = authorizationSchemeGetter('bearer');

  it('should return null if not authorization header', async () => {
    const request = httpMocks.createRequest({ headers: {} });
    const token = await tokenGetter(request);
    expect(token).toBeNull();
  });

  ['TOKEN', 'Foo TOKEN'].forEach((value) => {
    it(`should return null if invalid authorization value (${value})`, async () => {
      const request = httpMocks.createRequest({ headers: { authorization: value } });
      const token = await tokenGetter(request);
      expect(token).toBeNull();
    });
  });

  ['BEARER', 'Bearer', 'bearer'].forEach((scheme) => {
    it(`should return the token if authorization header with valid scheme (${scheme})`, async () => {
      const request = httpMocks.createRequest({ headers: { authorization: `${scheme} TOKEN` } });
      const token = await tokenGetter(request);
      expect(token).toEqual('TOKEN');
    });
  });
});

describe('cookieGetter', () => {
  const tokenGetter = cookieGetter('session');

  it('should return null if no cookie', async () => {
    const request = httpMocks.createRequest({ headers: {} });
    const token = await tokenGetter(request);
    expect(token).toBeNull();
  });

  ['foo=bar', 'foo=bar;user=foo', ';'].forEach((cookie) => {
    it('should return null if no matching cookie', async () => {
      const request = httpMocks.createRequest({ headers: { cookie } });
      const token = await tokenGetter(request);
      expect(token).toBeNull();
    });
  });

  it('should return token if matching cookie', async () => {
    const request = httpMocks.createRequest({ headers: { cookie: 'foo=bar;session=TOKEN' } });
    const token = await tokenGetter(request);
    expect(token).toEqual('TOKEN');
  });
});
