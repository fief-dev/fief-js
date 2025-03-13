/**
 * Browser integration.
 *
 * @module
 */

import { Fief, FiefTokenResponse, FiefUserInfo } from './client';
import { getCrypto, ICryptoHelper } from './crypto';

/**
 * Interface that should follow a class to implement storage for authentication data.
 */
export interface IFiefAuthStorage {
  /**
   * Retrieve current user information from storage, if available.
   */
  getUserinfo(): FiefUserInfo | null;

  /**
   * Store current user information in storage.
   *
   * @param userinfo - The user information to store.
   */
  setUserinfo(userinfo: FiefUserInfo): void;

  /**
   * Remove current user information from storage.
   */
  clearUserinfo(): void;

  /**
   * Retrieve current token information from storage, if available.
   */
  getTokenInfo(): FiefTokenResponse | null;

  /**
   * Store current token information in storage.
   *
   * @param tokenInfo - The token information to store.
   */
  setTokenInfo(tokenInfo: FiefTokenResponse): void;

  /**
   * Remove current token information from storage.
   */
  clearTokeninfo(): void;

  /**
   * Retrieve PKCE code verifier from storage, if any.
   *
   * @see [PKCE](https://docs.fief.dev/going-further/pkce/)
   */
  getCodeVerifier(): string | null;

  /**
   * Set a PKCE code verifier in storage.
   *
   * @param code - The code verifier to store.
   *
   * @see [PKCE](https://docs.fief.dev/going-further/pkce/)
   */
  setCodeVerifier(code: string): void;

  /**
   * Remove PKCE code verifier from storage.
   *
   * @see [PKCE](https://docs.fief.dev/going-further/pkce/)
   */
  clearCodeVerifier(): void;
}

/**
 * Implementation of an authentication storage using standard browser `sessionStorage`.
 *
 * @see [Window.sessionStorage](https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage)
 */
class FiefAuthStorage implements IFiefAuthStorage {
  private storage: Storage;

  private static readonly USERINFO_STORAGE_KEY = 'fief-userinfo';

  private static readonly TOKEN_INFO_STORAGE_KEY = 'fief-tokeninfo';

  private static readonly CODE_VERIFIER_STORAGE_KEY = 'fief-codeverifier';

  constructor() {
    this.storage = window.sessionStorage;
  }

  public getUserinfo(): FiefUserInfo | null {
    const value = this.storage.getItem(FiefAuthStorage.USERINFO_STORAGE_KEY);
    if (!value) {
      return null;
    }
    return JSON.parse(value);
  }

  public setUserinfo(userinfo: Record<string, any>): void {
    this.storage.setItem(FiefAuthStorage.USERINFO_STORAGE_KEY, JSON.stringify(userinfo));
  }

  public clearUserinfo(): void {
    this.storage.removeItem(FiefAuthStorage.USERINFO_STORAGE_KEY);
  }

  public getTokenInfo(): FiefTokenResponse | null {
    const value = this.storage.getItem(FiefAuthStorage.TOKEN_INFO_STORAGE_KEY);
    if (!value) {
      return null;
    }
    return JSON.parse(value);
  }

  public setTokenInfo(tokenInfo: FiefTokenResponse): void {
    this.storage.setItem(FiefAuthStorage.TOKEN_INFO_STORAGE_KEY, JSON.stringify(tokenInfo));
  }

  public clearTokeninfo(): void {
    this.storage.removeItem(FiefAuthStorage.TOKEN_INFO_STORAGE_KEY);
  }

  public getCodeVerifier(): string | null {
    const value = this.storage.getItem(FiefAuthStorage.CODE_VERIFIER_STORAGE_KEY);
    if (!value) {
      return null;
    }
    return value;
  }

  public setCodeVerifier(code: string): void {
    this.storage.setItem(FiefAuthStorage.CODE_VERIFIER_STORAGE_KEY, code);
  }

  public clearCodeVerifier(): void {
    this.storage.removeItem(FiefAuthStorage.CODE_VERIFIER_STORAGE_KEY);
  }
}

export class FiefAuthError extends Error { }

export class FiefAuthAuthorizeError extends FiefAuthError {
  public error: string;

  public description: string | null;

  constructor(error: string, description: string | null = null) {
    super();
    this.error = error;
    this.description = description;
  }
}

export class FiefAuthNotAuthenticatedError extends FiefAuthError { }

/**
 * Helper class to integrate Fief authentication in a browser application.
 *
 * @example
 * ```ts
 * const fiefClient = new fief.Fief({
 *     baseURL: 'https://example.fief.dev',
 *     clientId: 'YOUR_CLIENT_ID',
 * });
 * const fiefAuth = new fief.browser.FiefAuth(fiefClient);
 * ```
 */
export class FiefAuth {
  private client: Fief;

  private storage: IFiefAuthStorage;

  private crypto: ICryptoHelper;

  private pendingAuthCallbacks: Set<string>;

  /**
   * @param client - Instance of a {@link Fief} client.
   */
  constructor(client: Fief, storage?: IFiefAuthStorage) {
    this.client = client;
    if (storage !== undefined) {
      this.storage = storage;
    } else {
      this.storage = new FiefAuthStorage();
    }
    this.crypto = getCrypto();
    this.pendingAuthCallbacks = new Set();
  }

  /**
   * Return whether there is a valid user session in the browser.
   *
   * @returns `true` if there is a valid user session, `false` otherwise.
   *
   * @example
   * ```ts
   * const isAuthenticated = fiefAuth.isAuthenticated();
   * ```
   */
  public isAuthenticated(): boolean {
    return this.storage.getTokenInfo() !== null;
  }

  /**
   * Return the user information object available in session, or `null` if no current session.
   *
   * @returns The user information, or null if not available.
   *
   * @example
   * ```ts
   * const userinfo = fiefAuth.getUserinfo();
   * ````
   */
  public getUserinfo(): FiefUserInfo | null {
    return this.storage.getUserinfo();
  }

  /**
   * Return the token information object available in session, or `null` if no current session.
   *
   * @returns The token information, or null if not available.
   *
   * @example
   * ```ts
   * const tokenInfo = fiefAuth.getTokenInfo();
   * ```
   */
  public getTokenInfo(): FiefTokenResponse | null {
    return this.storage.getTokenInfo();
  }

  /**
   * Start a Fief authorization process and perform the redirection.
   *
   * Under the hood, it automatically handles
   * the [PKCE code challenge](https://docs.fief.dev/going-further/pkce/).
   *
   * @param redirectURI - Your callback URI where the user
   * will be redirected after Fief authentication.
   * @param parameters.state - Optional string that will be returned back
   * in the callback parameters to allow you to retrieve state information.
   * @param parameters.scope - Optional list of scopes to ask for. Defaults to `['openid']`.
   * @param parameters.lang - Optional parameter to set the user locale.
   * Should be a valid [RFC 3066](https://www.rfc-editor.org/rfc/rfc3066) language identifier, like `fr` or `pt-PT`.
   * @param parameters.extrasParams - Optional object containing [specific parameters](https://docs.fief.dev/going-further/authorize-url/).
   *
   * @example
   * ```ts
   * fiefAuth.redirectToLogin('http://localhost:8080/callback.html');
   * ```
   *
   * @example
   * Set the user locale.
   * ```ts
   * fiefAuth.redirectToLogin('http://localhost:8080/callback.html', { lang: 'fr-FR' });
   * ```
   */
  public async redirectToLogin(
    redirectURI: string,
    parameters?: {
      state?: string,
      scope?: string[],
      lang?: string,
      extrasParams?: Record<string, string>,
    },
  ): Promise<void> {
    const codeVerifier = await this.crypto.generateCodeVerifier();
    const codeChallenge = await this.crypto.getCodeChallenge(codeVerifier, 'S256');
    this.storage.setCodeVerifier(codeVerifier);

    const authorizeURL = await this.client.getAuthURL({
      redirectURI,
      scope: parameters?.scope || ['openid'],
      codeChallenge,
      codeChallengeMethod: 'S256',
      ...parameters?.state ? { state: parameters.state } : {},
      ...parameters?.lang ? { lang: parameters.lang } : {},
      ...parameters?.extrasParams ? { extrasParams: parameters.extrasParams } : {},
    });
    window.location.href = authorizeURL;
  }

  /**
   * Complete the Fief authentication process by exchanging
   * the authorization code available in query parameters
   * and store the tokens and user information in the browser session.
   *
   * Under the hood, it automatically handles
   * the [PKCE code challenge](https://docs.fief.dev/going-further/pkce/).
   *
   * @param redirectURI - The exact same `redirectURI` you passed to the authorization URL.
   */
  public async authCallback(redirectURI: string): Promise<void> {
    const params = new URLSearchParams(window.location.search);
    const error = params.get('error');
    const errorDescription = params.get('error_description');
    const code = params.get('code');

    if (error !== null) {
      throw new FiefAuthAuthorizeError(error, errorDescription);
    } else if (code === null) {
      throw new FiefAuthAuthorizeError('missing_code');
    }

    // Prevent authCallback request to be triggered twice with the same code.
    // Useful for frameworks like React which tends to re-render agressively.
    if (this.pendingAuthCallbacks.has(code)) {
      return;
    }

    const codeVerifier = this.storage.getCodeVerifier();
    this.storage.clearCodeVerifier();

    this.pendingAuthCallbacks.add(code);

    const [tokenResponse, userinfo] = await this.client.authCallback(
      code,
      redirectURI,
      codeVerifier || undefined,
    );

    this.pendingAuthCallbacks.delete(code);

    this.storage.setTokenInfo(tokenResponse);
    this.storage.setUserinfo(userinfo);
  }

  /**
   * Refresh user information from the Fief API using the access token available in session.
   *
   * The fresh user information is returned **and** automatically updated in the session storage.
   *
   * @returns The refreshed user information
   *
   * @example
   * ```ts
   * fiefAuth.refreshUserinfo()
   *     .then((userinfo) => {
   *         console.log(userinfo);
   *     })
   *     .catch((err) => {
   *         if (err instance of fief.browser.FiefAuthNotAuthenticatedError) {
   *             console.error('User is not logged in');
   *         }
   *     })
   * ;
   * ```
   */
  public async refreshUserinfo(): Promise<FiefUserInfo> {
    const tokenInfo = this.getTokenInfo();
    if (tokenInfo === null) {
      throw new FiefAuthNotAuthenticatedError();
    }
    const userinfo = await this.client.userinfo(tokenInfo.access_token);
    this.storage.setUserinfo(userinfo);
    return userinfo;
  }

  /**
   * Clear the access token and the user information from the browser storage
   * and redirect to the Fief logout endpoint.
   *
   * @param redirectURI - A valid URL where the user will be redirected after the logout process.
   *
   * @example
   * ```ts
   * fiefAuth.logout('http://localhost:8080')
   * ```
   */
  public async logout(redirectURI: string): Promise<void> {
    this.storage.clearUserinfo();
    this.storage.clearTokeninfo();

    const logoutURL = await this.client.getLogoutURL({ redirectURI });
    window.location.href = logoutURL;
  }
}
