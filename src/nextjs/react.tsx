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

/**
 * {@link FiefAuthProvider} properties.
 */
export interface FiefAuthProviderProps {
  /**
   * Path to the current user API.
   *
   * This API is provided by {@link FiefAuth.currentUser}.
   *
   * **Example:** `/api/current-user`
   */
  currentUserPath: string;
  children?: ReactNode;
}

/**
 * Provide the necessary context for Fief, especially the user session state.
 *
 * Every component nested inside this component will have access to the Fief hooks.
 *
 * @param props - Component properties.
 *
 * @example
 * ```tsx
 * import { FiefAuthProvider } from '@fief/fief/nextjs';
 * import type { AppProps } from 'next/app';
 *
 * function MyApp({ Component, pageProps }: AppProps) {
 *   return (
 *     <FiefAuthProvider currentUserPath="/api/current-user">
 *       <Component {...pageProps} />
 *     </FiefAuthProvider>
 *   );
 * };
 *
 * export default MyApp;
 * ```
 */
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

/**
 * Return the user information object available in session, or `null` if no current session.
 *
 * @returns The user information, or null if not available.
 *
 * @example
 * ```tsx
 * const userinfo = useFiefUserinfo();
 * ````
 */
export const useFiefUserinfo = (): FiefUserInfo | null => {
  const { state } = useContext(FiefAuthContext);
  return state.userinfo;
};

/**
 * Return the access token information object available in session, or `null` if no current session.
 *
 * @returns The access token information, or null if not available.
 *
 * @example
 * ```tsx
 * const accessTokenInfo = useFiefAccessTokenInfo();
 * ```
 */
export const useFiefAccessTokenInfo = (): FiefSafeAccessTokenInfo | null => {
  const { state } = useContext(FiefAuthContext);
  return state.accessTokenInfo;
};

/**
 * Return whether there is a valid user session.
 *
 * @returns `true` if there is a valid user session, `false` otherwise.
 *
 * @example
 * ```tsx
 * const isAuthenticated = useFiefIsAuthenticated();
 * ```
 */
export const useFiefIsAuthenticated = (): boolean => {
  const accessTokenInfo = useFiefAccessTokenInfo();
  return accessTokenInfo !== null;
};

/**
 * Return a function to refresh the user information from the API.
 *
 * @returns A refresh function.
 *
 * @example
 * ```tsx
 * const userinfo = useFiefUserinfo();
 * const refresh = useFiefRefresh();
 *
 * return (
 *     <>
 *         <p>User: {userinfo.email}</p>
 *         <button type="button" onClick={refresh}>Refresh user</button>
 *     </>
 * );
 * ```
 */
export const useFiefRefresh = (): () => void => {
  const { refresh } = useContext(FiefAuthContext);
  return refresh;
};
