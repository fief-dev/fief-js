import * as React from 'react';
import { useMemo } from 'react';

import { FiefAuth } from '../browser';
import { Fief, FiefParameters } from '../client';
import FiefAuthContext from './context';

interface FiefAuthProviderProps extends FiefParameters { }

const FiefAuthProvider: React.FunctionComponent<FiefAuthProviderProps> = (props) => {
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

  const fiefAuth = useMemo(() => new FiefAuth(fief), [fief]);

  return (
    <FiefAuthContext.Provider value={fiefAuth}>
      {props.children}
    </FiefAuthContext.Provider>
  );
};

export default FiefAuthProvider;
