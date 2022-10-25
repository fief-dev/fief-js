/**
 * In Node 16 and 17, Fetch API is not available globally,
 * which is required to run Next.js unit tests.
 *
 * To circumvent this, we export manually the versions from node-fetch.
 */
module.exports = async (_globalConfig, _projectConfig) => {
  // eslint-disable-next-line global-require
  const { Headers, Request, Response } = require('node-fetch');
  globalThis.Headers = Headers;
  globalThis.Request = Request;
  globalThis.Response = Response;
};
