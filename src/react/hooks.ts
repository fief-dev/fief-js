import { useContext } from 'react';

import type { FiefAuth } from '../browser';
import { FiefAuthContext } from './context';

export const useFiefAuth = (): FiefAuth => {
  const { auth } = useContext(FiefAuthContext);
  return auth;
};

export const useFiefUserinfo = (): Record<string, any> | null => {
  const { state } = useContext(FiefAuthContext);
  return state.userinfo;
};

export const useFiefTokenInfo = (): Record<string, any> | null => {
  const { state } = useContext(FiefAuthContext);
  return state.tokenInfo;
};

export const useFiefIsAuthenticated = (): boolean => {
  const userinfo = useFiefUserinfo();
  return userinfo !== null;
};
