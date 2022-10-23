import * as React from 'react';
import { useReducer } from 'react';

import { IFiefAuthStorage } from '../browser';
import { FiefTokenResponse, FiefUserInfo } from '../client';

export interface FiefAuthState {
  userinfo: FiefUserInfo | null;
  tokenInfo: FiefTokenResponse | null;
}

interface SetUserInfoAuthReducerAction {
  type: 'setUserinfo';
  value: FiefUserInfo;
}

interface ClearUserInfoAuthReducerAction {
  type: 'clearUserinfo';
}

interface SetTokenInfoAuthReducerAction {
  type: 'setTokenInfo';
  value: FiefTokenResponse;
}

interface ClearTokenInfoAuthReducerAction {
  type: 'clearTokenInfo';
}

type AuthReducerAction = (
  SetUserInfoAuthReducerAction |
  ClearUserInfoAuthReducerAction |
  SetTokenInfoAuthReducerAction |
  ClearTokenInfoAuthReducerAction
);

const reducer = (state: FiefAuthState, action: AuthReducerAction): FiefAuthState => {
  switch (action.type) {
    case 'setUserinfo':
      return { ...state, userinfo: action.value };
    case 'clearUserinfo':
      return { ...state, userinfo: null };
    case 'setTokenInfo':
      return { ...state, tokenInfo: action.value };
    case 'clearTokenInfo':
      return { ...state, tokenInfo: null };
    default:
      throw new Error();
  }
};

export const useAuthStorageReducer = () => useReducer(reducer, { userinfo: null, tokenInfo: null });

export class FiefReactAuthStorage implements IFiefAuthStorage {
  private state: FiefAuthState;

  private dispatch: React.Dispatch<AuthReducerAction>;

  private sessionStorage: Storage;

  private static readonly CODE_VERIFIER_STORAGE_KEY = 'fief-codeverifier';

  constructor(state: FiefAuthState, dispatch: React.Dispatch<AuthReducerAction>) {
    this.state = state;
    this.dispatch = dispatch;
    this.sessionStorage = window.sessionStorage;
  }

  public getUserinfo(): FiefUserInfo | null {
    return this.state.userinfo || null;
  }

  public setUserinfo(userinfo: FiefUserInfo): void {
    this.dispatch({ type: 'setUserinfo', value: userinfo });
  }

  public clearUserinfo(): void {
    this.dispatch({ type: 'clearUserinfo' });
  }

  public getTokenInfo(): FiefTokenResponse | null {
    return this.state.tokenInfo || null;
  }

  public setTokenInfo(tokenInfo: FiefTokenResponse): void {
    this.dispatch({ type: 'setTokenInfo', value: tokenInfo });
  }

  public clearTokeninfo(): void {
    this.dispatch({ type: 'clearTokenInfo' });
  }

  public getCodeVerifier(): string | null {
    const value = this.sessionStorage.getItem(FiefReactAuthStorage.CODE_VERIFIER_STORAGE_KEY);
    if (!value) {
      return null;
    }
    return value;
  }

  public setCodeVerifier(code: string): void {
    this.sessionStorage.setItem(FiefReactAuthStorage.CODE_VERIFIER_STORAGE_KEY, code);
  }

  public clearCodeVerifier(): void {
    this.sessionStorage.removeItem(FiefReactAuthStorage.CODE_VERIFIER_STORAGE_KEY);
  }
}
