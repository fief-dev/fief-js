import React, {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useEffect,
  useReducer,
} from 'react';

import { FiefSafeAccessTokenInfo, FiefUserInfo } from '../client';

export interface FiefAuthState {
  userinfo: FiefUserInfo | null;
  accessTokenInfo: FiefSafeAccessTokenInfo | null;
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
  value: FiefSafeAccessTokenInfo;
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

export const useAuthStorageReducer = () => useReducer(
  reducer,
  {
    userinfo: null,
    accessTokenInfo: null,
  },
);

const stub = (): never => {
  throw new Error('You forgot to wrap your component in <FiefAuthProvider>.');
};

interface FiefAuthContextType {
  state: FiefAuthState;
  refresh: () => void;
}

// @ts-ignore
export const FiefAuthContext = createContext<FiefAuthContextType>(stub);

interface FiefAuthProviderProps {
  currentUserPath: string;
  children?: ReactNode;
}

export const FiefAuthProvider: React.FunctionComponent<FiefAuthProviderProps> = (props) => {
  const [state, dispatch] = useAuthStorageReducer();
  const refresh = useCallback(async () => {
    const response = await window.fetch(props.currentUserPath);
    if (response.status === 200) {
      const data = await response.json();
      dispatch({ type: 'setAccessTokenInfo', value: data.access_token_info });
      dispatch({ type: 'setUserinfo', value: data.userinfo });
    }
  }, [dispatch]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <FiefAuthContext.Provider value={{ state, refresh }}>
      {props.children}
    </FiefAuthContext.Provider>
  );
};

export const useFiefUserinfo = (): FiefUserInfo | null => {
  const { state } = useContext(FiefAuthContext);
  return state.userinfo;
};

export const useFiefAccessTokenInfo = (): FiefSafeAccessTokenInfo | null => {
  const { state } = useContext(FiefAuthContext);
  return state.accessTokenInfo;
};

export const useFiefIsAuthenticated = (): boolean => {
  const accessTokenInfo = useFiefAccessTokenInfo();
  return accessTokenInfo !== null;
};

export const useFiefRefresh = (): () => void => {
  const { refresh } = useContext(FiefAuthContext);
  return refresh;
};
