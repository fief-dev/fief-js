import axios, { Axios } from 'axios';
import * as jose from 'jose';
import * as qs from 'qs';
import { isValidHash } from './crypto';

export interface FiefTokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
}

export interface FiefAccessTokenInfo {
  id: string;
  scope: string[];
  permissions: string[];
  access_token: string;
}

export type FiefUserInfo = Record<string, any>;

export class FiefError extends Error { }
export class FiefAccessTokenInvalid extends FiefError { }
export class FiefAccessTokenExpired extends FiefError { }
export class FiefAccessTokenMissingScope extends FiefError { }
export class FiefAccessTokenMissingPermission extends FiefError { }
export class FiefIdTokenInvalid extends FiefError { }

export interface FiefParameters {
  baseURL: string;
  clientId: string;
  clientSecret?: string;
  encryptionKey?: string;
}

export class Fief {
  private baseURL: string;

  private clientId: string;

  private clientSecret?: string;

  private encryptionKey?: jose.KeyLike | Uint8Array;

  private client: Axios;

  private openIDConfiguration?: Record<string, any>;

  private jwks?: jose.JSONWebKeySet;

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

    this.client = axios.create({
      baseURL: this.baseURL,
      ...this.clientSecret ? {
        auth: { username: this.clientId, password: this.clientSecret },
      } : {},
    });
  }

  public async getAuthURL(parameters: {
    redirectURI: string;
    state?: string;
    scope?: string[];
    codeChallenge?: string,
    codeChallengeMethod?: 'plain' | 'S256',
    extrasParams?: Record<string, string>;
  }): Promise<string> {
    const openIDConfiguration = await this.getOpenIDConfiguration();

    const {
      redirectURI,
      state,
      scope,
      codeChallenge,
      codeChallengeMethod,
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
      ...extrasParams ? { ...extrasParams } : {},
    });

    const authorizationEndpoint = openIDConfiguration.authorization_endpoint;
    return `${authorizationEndpoint}?${redirectURIParams.toString()}`;
  }

  public async authCallback(
    code: string,
    redirectURI: string,
    codeVerifier?: string,
  ): Promise<[FiefTokenResponse, FiefUserInfo]> {
    const openIDConfiguration = await this.getOpenIDConfiguration();
    const payload = qs.stringify({
      grant_type: 'authorization_code',
      client_id: this.clientId,
      code,
      redirect_uri: redirectURI,
      ...codeVerifier ? { code_verifier: codeVerifier } : {},
    });

    const { data } = await this.client.post<FiefTokenResponse>(
      openIDConfiguration.token_endpoint,
      payload,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      },
    );

    const userinfo = await this.decodeIDToken({
      idToken: data.id_token,
      jwks: await this.getJWKS(),
      code,
      accessToken: data.access_token,
    });

    return [data, userinfo];
  }

  public async authRefreshToken(
    refreshToken: string,
    scope?: string[],
  ): Promise<[FiefTokenResponse, FiefUserInfo]> {
    const openIDConfiguration = await this.getOpenIDConfiguration();
    const payload = qs.stringify({
      grant_type: 'refresh_token',
      client_id: this.clientId,
      refresh_token: refreshToken,
      ...scope ? { scope: scope.join(' ') } : {},
    });

    const { data } = await this.client.post<FiefTokenResponse>(
      openIDConfiguration.token_endpoint,
      payload,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      },
    );

    const userinfo = await this.decodeIDToken({
      idToken: data.id_token,
      jwks: await this.getJWKS(),
      accessToken: data.access_token,
    });

    return [data, userinfo];
  }

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

  public async userinfo(accessToken: string): Promise<FiefUserInfo> {
    const openIDConfiguration = await this.getOpenIDConfiguration();
    const { data } = await this.client.get<FiefUserInfo>(
      openIDConfiguration.userinfo_endpoint,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );
    return data;
  }

  public async updateProfile(
    accessToken: string,
    data: Record<string, any>,
  ): Promise<FiefUserInfo> {
    const updateProfileEndpoint = `${this.baseURL}/api/profile`;

    const { data: userinfo } = await this.client.patch<FiefUserInfo>(
      updateProfileEndpoint,
      {
        data,
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );
    return userinfo;
  }

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
    const { data } = await this.client.get<Record<string, any>>('/.well-known/openid-configuration');
    this.openIDConfiguration = data;
    return data;
  }

  private async getJWKS(): Promise<jose.JSONWebKeySet> {
    if (this.jwks !== undefined) {
      return this.jwks;
    }
    const openIDConfiguration = await this.getOpenIDConfiguration();
    const { data } = await this.client.get<jose.JSONWebKeySet>(openIDConfiguration.jwks_uri);
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
        if (!code || !(await isValidHash(code, claims.c_hash as string))) {
          throw new FiefIdTokenInvalid();
        }
      }

      if (claims.at_hash !== undefined) {
        if (!accessToken || !(await isValidHash(accessToken, claims.at_hash as string))) {
          throw new FiefIdTokenInvalid();
        }
      }

      return claims;
    } catch (err) {
      if (err instanceof jose.errors.JOSEError) {
        throw new FiefIdTokenInvalid();
      }
      throw err;
    }
  }
}
