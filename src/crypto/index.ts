import { CryptoHelperError, ICryptoHelper } from './base';
import { BrowserCryptoHelper } from './browser';
import { NodeJSCryptoHelper } from './node';

/**
 * Return a {@link ICryptoHelper} implementation suitable for the current environment.
 *
 * @returns A {@link ICryptoHelper}
 */
export const getCrypto = (): ICryptoHelper => {
  // Browser
  // eslint-disable-next-line no-restricted-globals
  if (typeof window !== 'undefined' || typeof self !== 'undefined') {
    return new BrowserCryptoHelper();
  }

  // NodeJS
  if (typeof require === 'function') {
    return new NodeJSCryptoHelper();
  }

  throw new CryptoHelperError('Cannot find a crypto implementation for your environment');
};

export { CryptoHelperError, ICryptoHelper };
