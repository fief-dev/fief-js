import nodeFetch from 'node-fetch';

export class FetchHelperError extends Error {}

export const getFetch = (): typeof fetch => {
  if (typeof window !== 'undefined' && window.fetch) {
    return window.fetch.bind(window);
  }

  // eslint-disable-next-line no-restricted-globals
  if (typeof self !== 'undefined' && self.fetch) {
    // eslint-disable-next-line no-restricted-globals
    return self.fetch.bind(self);
  }

  if (typeof globalThis !== 'undefined' && globalThis.fetch) {
    return globalThis.fetch.bind(globalThis);
  }

  if (typeof require === 'function') {
    // @ts-ignore
    return nodeFetch as typeof fetch;
  }

  throw new FetchHelperError('Cannot find a fetch implementation for your environment');
};
