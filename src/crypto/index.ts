import { CryptoHelperError, ICryptoHelper } from './base';
import { BrowserCryptoHelper } from './browser';
import { NodeJSCryptoHelper } from './node';

/**
 * Return a {@link ICryptoHelper} implementation suitable for the current environment.
 *
 * @returns A {@link ICryptoHelper}
 */
export const getCrypto = (): ICryptoHelper => {
  // Browser and workers
  if (
    typeof window !== 'undefined'
    // eslint-disable-next-line no-restricted-globals
    || typeof self !== 'undefined'
    // @ts-ignore
    // eslint-disable-next-line no-undef
    || (typeof EdgeRuntime !== 'undefined' && EdgeRuntime === 'vercel')
  ) {
    return new BrowserCryptoHelper();
  }

  // NodeJS
  if (typeof require === 'function') {
    return new NodeJSCryptoHelper();
  }

  throw new CryptoHelperError('Cannot find a crypto implementation for your environment');
};

export { CryptoHelperError, ICryptoHelper };
