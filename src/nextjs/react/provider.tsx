import React, {
  useCallback,
  useEffect,
} from 'react';

import { FiefAuthContext } from './context';
import { FiefAuthState, useAuthStorageReducer } from './state';

/**
 * {@link FiefAuthProvider} properties.
 */
interface FiefAuthProviderProps {
  /**
   * Initial state of the user session.
   *
   * Can be passed directly from server-side functions.
   */
  state: FiefAuthState;
  /**
   * Path to the current user API.
   *
   * This API is provided by {@link FiefAuth.currentUser}.
   *
   * **Example:** `/api/current-user`
   */
  currentUserPath: string;
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
const FiefAuthProvider: React.FunctionComponent<React.PropsWithChildren<FiefAuthProviderProps>> = (
  props,
) => {
  const [state, dispatch] = useAuthStorageReducer();
  const refresh = useCallback(async (useCache?: boolean) => {
    const refreshParam = useCache === undefined ? false : !useCache;
    const response = await window.fetch(`${props.currentUserPath}?refresh=${refreshParam}`);
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

export {
  FiefAuthProvider,
};
