import { createContext } from 'react';

import type { FiefAuth } from '../browser';

const stub = (): never => {
  throw new Error('You forgot to wrap your component in <FiefProvider>.');
};

// @ts-ignore
const FiefAuthContext = createContext<FiefAuth>(stub);

export default FiefAuthContext;
