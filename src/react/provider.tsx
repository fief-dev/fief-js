import * as React from 'react';
import { useMemo } from 'react';

import { FiefAuth } from '../browser';
import { Fief, FiefParameters } from '../client';
import { FiefAuthContext } from './context';
import { FiefReactAuthStorage, useAuthStorageReduce } from './storage';

export interface FiefAuthProviderProps extends FiefParameters { }

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
