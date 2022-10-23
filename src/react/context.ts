import { createContext } from 'react';

import type { FiefAuth } from '../browser';
import { FiefAuthState } from './storage';

const stub = (): never => {
  throw new Error('You forgot to wrap your component in <FiefAuthProvider>.');
};

/**
 * Context storing the {@link index.browser.FiefAuth} helper and the authentication state.
 */
// @ts-ignore
export const FiefAuthContext = createContext<{ auth: FiefAuth, state: FiefAuthState }>(stub);
