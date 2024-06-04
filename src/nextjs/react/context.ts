import {
  createContext,
} from 'react';

import { FiefAuthState } from './state';

const stub = (): never => {
  throw new Error('You forgot to wrap your component in <FiefAuthProvider>.');
};

/**
 * Function to refresh the user information from the API.
 *
 * @param useCache - If `true`, the data will be read from your server cache (much faster).
 * If `false`, the data will be retrieved from the Fief API (fresher data).
 * Defaults to `true`.
 */
type RefreshFunction = (useCache?: boolean) => Promise<void>;

interface FiefAuthContextType {
  state: FiefAuthState;
  refresh: RefreshFunction;
}

// @ts-ignore
const FiefAuthContext = createContext<FiefAuthContextType>(stub);

export {
  FiefAuthContext,
};
export type {
  RefreshFunction,
};
