import * as React from 'react';
import { useMemo, ReactNode } from 'react';

import { FiefAuth } from '../browser';
import { Fief, FiefParameters } from '../client';
import { FiefAuthContext } from './context';
import { FiefReactAuthStorage, useAuthStorageReduce } from './storage';

export interface FiefAuthProviderProps extends FiefParameters { children?: ReactNode }

/**
 * Provide the necessary context for Fief, especially the Fief client and user session state.
 *
 * Every component nested inside this component will have access to the Fief hooks.
 *
 * @param props - Component properties.
 *
 * @example
 * ```ts
 * function App() {
 *   return (
 *     <FiefAuthProvider
 *       baseURL="https://example.fief.dev"
 *       clientId="YOUR_CLIENT_ID"
 *     >
 *       <div className="App">
 *         <h1>Fief React example</h1>
 *       </div>
 *     </FiefAuthProvider>
 *   );
 * }
 * ```
 */
export const FiefAuthProvider: React.FunctionComponent<FiefAuthProviderProps> = (props) => {
  const {
    baseURL,
    clientId,
    clientSecret,
    encryptionKey,
  } = props;

  const fief = useMemo(() => new Fief({
    baseURL,
    clientId,
    clientSecret,
    encryptionKey,
  }), [baseURL, clientId, clientSecret, encryptionKey]);

  const [state, dispatch] = useAuthStorageReduce();
  const storage = useMemo(() => new FiefReactAuthStorage(state, dispatch), [state, dispatch]);
  const fiefAuth = useMemo(() => new FiefAuth(fief, storage), [fief]);

  return (
    <FiefAuthContext.Provider value={{ auth: fiefAuth, state }}>
      {props.children}
    </FiefAuthContext.Provider>
  );
};
