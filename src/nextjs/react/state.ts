import {
  useReducer,
} from 'react';

import type { FiefAccessTokenInfo, FiefUserInfo } from '../../client';

interface FiefAuthState {
  userinfo: FiefUserInfo | null;
  accessTokenInfo: FiefAccessTokenInfo | null;
}

interface SetUserInfoAuthReducerAction {
  type: 'setUserinfo';
  value: FiefUserInfo;
}

interface ClearUserInfoAuthReducerAction {
  type: 'clearUserinfo';
}

interface SetAccessTokenInfoAuthReducerAction {
  type: 'setAccessTokenInfo';
  value: FiefAccessTokenInfo;
}

interface ClearAccessTokenInfoAuthReducerAction {
  type: 'clearAccessTokenInfo';
}

type AuthReducerAction = (
  SetUserInfoAuthReducerAction |
  ClearUserInfoAuthReducerAction |
  SetAccessTokenInfoAuthReducerAction |
  ClearAccessTokenInfoAuthReducerAction
);

const reducer = (state: FiefAuthState, action: AuthReducerAction): FiefAuthState => {
  switch (action.type) {
    case 'setUserinfo':
      return { ...state, userinfo: action.value };
    case 'clearUserinfo':
      return { ...state, userinfo: null };
    case 'setAccessTokenInfo':
      return { ...state, accessTokenInfo: action.value };
    case 'clearAccessTokenInfo':
      return { ...state, accessTokenInfo: null };
    default:
      throw new Error();
  }
};

const useAuthStorageReducer = () => useReducer(
  reducer,
  {
    userinfo: null,
    accessTokenInfo: null,
  },
);

export {
  useAuthStorageReducer,
};
export type { FiefAuthState };
