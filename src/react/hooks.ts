import { useContext } from 'react';

import type { FiefAuth } from '../browser';
import FiefAuthContext from './context';

export const useFiefAuth = (): FiefAuth => {
  const fiefAuth = useContext(FiefAuthContext);
  return fiefAuth;
};

export const useFiefIsAuthenticated = (): boolean => {
  const fiefAuth = useFiefAuth();
  return fiefAuth.isAuthenticated();
};
