import * as jose from 'jose';

import { getCrypto, ICryptoHelper } from './crypto';
import { getFetch } from './fetch';

const serializeQueryString = (object: Record<string, string>): string => {
  const elements: string[] = [];
  Object.keys(object).forEach((key) => {
    if (Object.prototype.hasOwnProperty.call(object, key)) {
      elements.push(`${encodeURIComponent(key)}=${encodeURIComponent(object[key])}`);
    }
  });
  return elements.join('&');
};

/**
 * Object containing the tokens and related information
 * returned by Fief after a successful authentication.
 */
export interface FiefTokenResponse {
  /**
   * Access token you can use to call the Fief API.
   */
  access_token: string;

  /**
   * ID token containing user information.
   */
  id_token: string;

  /**
   * Type of token, usually `bearer`.
   */
  token_type: string;

  /**
   * Number of seconds after which the tokens will expire.
   */
  expires_in: number;

  /**
   * Token provided only if scope `offline_access` was granted.
   * Allows you to retrieve fresh tokens using the {@link Fief#authRefreshToken} method.
   */
  refresh_token?: string;
}

/**
 * Typed dictionary containing information about the access token.
 *
 * **Example:**
 *
 * ```json
 * {
 *     "id": "aeeb8bfa-e8f4-4724-9427-c3d5af66190e",
 *     "scope": ["openid", "required_scope"],
 *     "permissions": ["castles:read", "castles:create", "castles:update", "castles:delete"],
 *     "access_token": "ACCESS_TOKEN",
 * }
 * ```
 */
export interface FiefAccessTokenInfo {
  /**
   * ID of the user.
   */
  id: string;

  /**
   * List of granted scopes for this access token.
   */
  scope: string[];

  /**
   * List of [granted permissions](https://docs.fief.dev/getting-started/access-control/) for this user.
   */
  permissions: string[];

  /**
   * Access token you can use to call the Fief API.
   */
  access_token: string;
}

/**
 * Dictionary containing user information.
 *
 *
 * **Example:**
 *
 * ```json
 * {
 *     "sub": "aeeb8bfa-e8f4-4724-9427-c3d5af66190e",
 *     "email": "anne@bretagne.duchy",
 *     "tenant_id": "c91ecb7f-359c-4244-8385-51ecd6c0d06b",
 *     "fields": {
 *         "first_name": "Anne",
 *         "last_name": "De Bretagne"
 *     }
 * }
 * ```
 */
export interface FiefUserInfo extends jose.JWTPayload {
  /**
   * ID of the user.
   */
  sub: string;

  /**
   * Email address of the user.
   */
  email: string;

  /**
   * ID of the [tenant](https://docs.fief.dev/getting-started/tenants/) associated to the user.
   */
  tenant_id: string;

  /**
   * [User fields](https://docs.fief.dev/getting-started/user-fields/) values for this user, indexed by their slug.
   */
  fields: Record<string, any>;
}

export class FiefError extends Error { }
export class FiefAccessTokenInvalid extends FiefError { }
export class FiefAccessTokenExpired extends FiefError { }
export class FiefAccessTokenMissingScope extends FiefError { }
export class FiefAccessTokenMissingPermission extends FiefError { }
export class FiefIdTokenInvalid extends FiefError { }

/**
 * Constructor parameters for the Fief client.
 */
export interface FiefParameters {
  /**
   * Base URL of your Fief tenant.
   */
  baseURL: string;

  /**
   * ID of your Fief client.
   */
  clientId: string;

  /**
   * Secret of your Fief client.
   *
   * It's not recommended to use it in the context of a browser app,
   * since it can be easily found by the end-user in the source code.
   * The recommended way is to use a [Public client](https://docs.fief.dev/getting-started/clients/#public-clients).
   */
  clientSecret?: string;

  /**
   * Encryption key of your Fief client.
   * Necessary only if ID Token encryption is enabled.
   *
   * @see [ID Token encryption](https://docs.fief.dev/going-further/id-token-encryption/)
   */
  encryptionKey?: string;
}

/**
 * Fief authentication client.
 *
 * @example
 * ```ts
 *  const fief = new Fief({
 *   baseURL: 'https://example.fief.dev',
 *   clientId: 'YOUR_CLIENT_ID',
 *   clientSecret: 'YOUR_CLIENT_SECRET',
 * });
 * ```
 */
export class Fief {
  private baseURL: string;

  private clientId: string;

  private clientSecret?: string;

  private encryptionKey?: jose.KeyLike | Uint8Array;

  private fetch: typeof fetch;

  private openIDConfiguration?: Record<string, any>;

  private jwks?: jose.JSONWebKeySet;

  private crypto: ICryptoHelper;

  constructor(parameters: FiefParameters) {
    this.baseURL = parameters.baseURL;
    this.clientId = parameters.clientId;
    this.clientSecret = parameters.clientSecret;

    if (parameters.encryptionKey !== undefined) {
      jose
        .importJWK(JSON.parse(parameters.encryptionKey), 'RSA-OAEP-256')
        .then((encryptionKey) => {
          this.encryptionKey = encryptionKey;
        })
      ;
    }

    this.fetch = getFetch();

    this.crypto = getCrypto();
  }

  /**
   * Return an authorization URL.
   *
   * @param parameters.redirectURI - Your callback URI where the user
   * will be redirected after Fief authentication.
   * @param parameters.state - Optional string that will be returned back
   * in the callback parameters to allow you to retrieve state information.
   * @param parameters.scope - Optional list of scopes to ask for.
   * @param parameters.codeChallenge - Optional code challenge for [PKCE process](https://docs.fief.dev/going-further/pkce/).
   * @param parameters.codeChallengeMethod - Method used to hash the PKCE code challenge.
   * @param parameters.lang - Optional parameter to set the user locale.
   * Should be a valid [RFC 3066](https://www.rfc-editor.org/rfc/rfc3066) language identifier, like `fr` or `pt-PT`.
   * @param parameters.extrasParams - Optional object containing [specific parameters](https://docs.fief.dev/going-further/authorize-url/).
   *
   * @returns The authorization URL.
   *
   * @example
   * ```ts
   * const authURL = await fief.getAuthURL({
   *     redirectURI: 'http://localhost:8000/callback',
   *     scope: ['openid'],
   * );
   * ```
   */
  public async getAuthURL(parameters: {
    redirectURI: string;
    state?: string;
    scope?: string[];
    codeChallenge?: string,
    codeChallengeMethod?: 'plain' | 'S256',
    lang?: string;
    extrasParams?: Record<string, string>;
  }): Promise<string> {
    const openIDConfiguration = await this.getOpenIDConfiguration();

    const {
      redirectURI,
      state,
      scope,
      codeChallenge,
      codeChallengeMethod,
      lang,
      extrasParams,
    } = parameters;

    const redirectURIParams = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: redirectURI,
      ...state ? { state } : {},
      ...codeChallenge ? { code_challenge: codeChallenge } : {},
      ...codeChallengeMethod ? { code_challenge_method: codeChallengeMethod } : {},
      ...state ? { state } : {},
      ...scope ? { scope: scope.join(' ') } : {},
      ...lang ? { lang } : {},
      ...extrasParams ? { ...extrasParams } : {},
    });

    const authorizationEndpoint = openIDConfiguration.authorization_endpoint;
    return `${authorizationEndpoint}?${redirectURIParams.toString()}`;
  }

  /**
   * Return a {@link FiefTokenResponse} and {@link FiefUserInfo}
   * in exchange of an authorization code.
   *
   * @param code - The authorization code.
   * @param redirectURI - The exact same `redirectURI` you passed to the authorization URL.
   * @param codeVerifier - The raw [PKCE](https://docs.fief.dev/going-further/pkce/) code
   * used to generate the code challenge during authorization.
   *
   * @returns A token response and user information.
   *
   * @example
   * ```ts
   * const [tokens, userinfo] = await fief.authCallback('CODE', 'http://localhost:8000/callback');
   * ```
   */
  public async authCallback(
    code: string,
    redirectURI: string,
    codeVerifier?: string,
  ): Promise<[FiefTokenResponse, FiefUserInfo]> {
    const openIDConfiguration = await this.getOpenIDConfiguration();
    const payload = serializeQueryString({
      grant_type: 'authorization_code',
      client_id: this.clientId,
      code,
      redirect_uri: redirectURI,
      ...this.clientSecret ? { client_secret: this.clientSecret } : {},
      ...codeVerifier ? { code_verifier: codeVerifier } : {},
    });

    const response = await this.fetch(
      openIDConfiguration.token_endpoint,
      {
        method: 'POST',
        body: payload,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      },
    );
    const data: FiefTokenResponse = await response.json();

    const userinfo = await this.decodeIDToken({
      idToken: data.id_token,
      jwks: await this.getJWKS(),
      code,
      accessToken: data.access_token,
    });

    return [data, userinfo];
  }

  /**
   * Return fresh {@link FiefTokenResponse} and {@link FiefUserInfo} in exchange of a refresh token.
   *
   * @param refreshToken - A valid refresh token.
   * @param scope - Optional list of scopes to ask for.
   * If not provided, the access token will share the same list of scopes
   * as requested the first time.
   * Otherwise, it should be a subset of the original list of scopes.
   *
   * @returns A token response and user information.
   *
   * @example
   * ```ts
   * const [tokens, userinfo] = await fief.authRefreshToken('REFRESH_TOKEN');
   * ```
   */
  public async authRefreshToken(
    refreshToken: string,
    scope?: string[],
  ): Promise<[FiefTokenResponse, FiefUserInfo]> {
    const openIDConfiguration = await this.getOpenIDConfiguration();
    const payload = serializeQueryString({
      grant_type: 'refresh_token',
      client_id: this.clientId,
      refresh_token: refreshToken,
      ...scope ? { scope: scope.join(' ') } : {},
    });

    const response = await this.fetch(
      openIDConfiguration.token_endpoint,
      {
        method: 'POST',
        body: payload,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      },
    );
    const data: FiefTokenResponse = await response.json();

    const userinfo = await this.decodeIDToken({
      idToken: data.id_token,
      jwks: await this.getJWKS(),
      accessToken: data.access_token,
    });

    return [data, userinfo];
  }

  /**
   * Check if an access token is valid and optionally that it has a required list of scopes,
   * or a required list of [permissions](https://docs.fief.dev/getting-started/access-control/).
   *
   * @param accessToken - The access token to validate.
   * @param requiredScopes - Optional list of scopes to check for.
   * @param requiredPermissions - Optional list of permissions to check for.
   *
   * @returns {@link FiefAccessTokenInfo}
   * @throws {@link FiefAccessTokenInvalid} if the access token is invalid.
   * @throws {@link FiefAccessTokenExpired} if the access token is expired.
   * @throws {@link FiefAccessTokenMissingScope} if a scope is missing.
   * @throws {@link FiefAccessTokenMissingPermission} if a permission is missing.
   *
   * @example
   * ```ts
   * try {
   *     accessTokenInfo = await fief.validateAccessToken('ACCESS_TOKEN', ['required_scope']);
   *     console.log(accessTokenInfo);
   * } catch (err) {
   *     if (err instanceof FiefAccessTokenInvalid) {
   *         console.error('Invalid access token');
   *     } else if (err instanceof FiefAccessTokenExpired) {
   *         console.error('Expired access token');
   *     } else if (err instanceof FiefAccessTokenMissingScope) {
   *         console.error('Missing required scope');
   *     }
   * }
   * ```
   */
  public async validateAccessToken(
    accessToken: string,
    requiredScopes?: string[],
    requiredPermissions?: string[],
  ): Promise<FiefAccessTokenInfo> {
    const signatureKeys = jose.createLocalJWKSet(await this.getJWKS());
    try {
      const { payload: claims } = await jose.jwtVerify(accessToken, signatureKeys);

      const scope = claims.scope as (string | undefined);
      if (scope === undefined) {
        throw new FiefAccessTokenInvalid();
      }
      const accessTokenScopes = scope.split(' ');

      if (requiredScopes) {
        requiredScopes.forEach((requiredScope) => {
          const inAccessTokenScopes = accessTokenScopes.some(
            (accessTokenScope) => accessTokenScope === requiredScope,
          );
          if (!inAccessTokenScopes) {
            throw new FiefAccessTokenMissingScope();
          }
        });
      }

      const permissions = claims.permissions as (string[] | undefined);
      if (permissions === undefined) {
        throw new FiefAccessTokenInvalid();
      }
      if (requiredPermissions) {
        requiredPermissions.forEach((requiredPermission) => {
          const inAccessTokenPermissions = permissions.some(
            (permission) => permission === requiredPermission,
          );
          if (!inAccessTokenPermissions) {
            throw new FiefAccessTokenMissingPermission();
          }
        });
      }

      return {
        id: claims.sub as string,
        scope: accessTokenScopes,
        permissions,
        access_token: accessToken,
      };
    } catch (err) {
      if (err instanceof jose.errors.JWTExpired) {
        throw new FiefAccessTokenExpired();
      } else if (err instanceof jose.errors.JOSEError) {
        throw new FiefAccessTokenInvalid();
      }
      throw err;
    }
  }

  /**
   * Return fresh {@link FiefUserInfo} from the Fief API using a valid access token.
   *
   * @param accessToken - A valid access token.
   *
   * @returns Fresh user information.
   *
   * @example
   * ```ts
   * userinfo = await fief.userinfo('ACCESS_TOKEN');
   * ```
   */
  public async userinfo(accessToken: string): Promise<FiefUserInfo> {
    const openIDConfiguration = await this.getOpenIDConfiguration();
    const response = await this.fetch(
      openIDConfiguration.userinfo_endpoint,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );
    const data: FiefUserInfo = await response.json();
    return data;
  }

  /**
   * Updates user information with the Fief API using a valid access token.
   *
   * @param accessToken - A valid access token.
   * @param data - An object containing the data to update.
   *
   * @returns Updated user information.
   *
   * @example
   * Update email address
   * ```ts
   * userinfo = await fief.updateProfile('ACCESS_TOKEN', { email: 'anne@nantes.city' })
   * ```
   *
   * @example
   * Update password
   * ```ts
   * userinfo = await fief.updateProfile('ACCESS_TOKEN', { password: 'hermine1' })
   * ```
   *
   * @example
   * To update [user field](https://docs.fief.dev/getting-started/user-fields/) values,
   * you need to nest them into a `fields` object, indexed by their slug.
   * ```ts
   * userinfo = await fief.update_profile('ACCESS_TOKEN', { fields: { first_name: 'Anne' } })
   * ```
   */
  public async updateProfile(
    accessToken: string,
    data: Record<string, any>,
  ): Promise<FiefUserInfo> {
    const updateProfileEndpoint = `${this.baseURL}/api/profile`;
    const response = await this.fetch(
      updateProfileEndpoint,
      {
        method: 'PATCH',
        body: JSON.stringify(data),
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );
    const userinfo = await response.json();
    return userinfo;
  }

  /**
   * Returns a logout URL.
   * If you redirect the user to this page, Fief will clear the session stored on its side.
   *
   * **You're still responsible for clearing your own session mechanism if any.**
   *
   * @param parameters.redirectURI - A valid URL where the user will be
   * redirected after the logout process.
   *
   * @returns The logout URL.
   *
   * @example
   * ```ts
   * const logoutURL = await fief.getLogoutURL({
   *    redirectURI: 'http://localhost:8000',
   * });
   * ```
   */
  public async getLogoutURL(parameters: { redirectURI: string }): Promise<string> {
    const params = new URLSearchParams({
      redirect_uri: parameters.redirectURI,
    });
    return `${this.baseURL}/logout?${params.toString()}`;
  }

  private async getOpenIDConfiguration(): Promise<Record<string, any>> {
    if (this.openIDConfiguration !== undefined) {
      return this.openIDConfiguration;
    }
    const response = await this.fetch(
      `${this.baseURL}/.well-known/openid-configuration`,
      {
        method: 'GET',
      },
    );
    const data = response.json();
    this.openIDConfiguration = data;
    return data;
  }

  private async getJWKS(): Promise<jose.JSONWebKeySet> {
    if (this.jwks !== undefined) {
      return this.jwks;
    }
    const openIDConfiguration = await this.getOpenIDConfiguration();
    const response = await this.fetch(
      openIDConfiguration.jwks_uri,
      {
        method: 'GET',
      },
    );
    const data: jose.JSONWebKeySet = await response.json();
    this.jwks = data;
    return data;
  }

  private async decodeIDToken(parameters: {
    idToken: string;
    jwks: jose.JSONWebKeySet;
    code?: string;
    accessToken?: string;
  }): Promise<FiefUserInfo> {
    const {
      idToken,
      jwks,
      code,
      accessToken,
    } = parameters;
    const signatureKeys = jose.createLocalJWKSet(jwks);

    try {
      let signedToken: string | Uint8Array = idToken;
      if (this.encryptionKey !== undefined) {
        const { plaintext } = await jose.compactDecrypt(idToken, this.encryptionKey);
        signedToken = plaintext;
      }

      const { payload: claims } = await jose.jwtVerify(signedToken, signatureKeys);

      if (claims.c_hash !== undefined) {
        if (!code || !(await this.crypto.isValidHash(code, claims.c_hash as string))) {
          throw new FiefIdTokenInvalid();
        }
      }

      if (claims.at_hash !== undefined) {
        if (
          !accessToken
          || !(await this.crypto.isValidHash(accessToken, claims.at_hash as string))
        ) {
          throw new FiefIdTokenInvalid();
        }
      }

      return claims as FiefUserInfo;
    } catch (err) {
      if (err instanceof jose.errors.JOSEError) {
        throw new FiefIdTokenInvalid();
      }
      throw err;
    }
  }
}
