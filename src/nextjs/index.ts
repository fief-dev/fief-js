import { IncomingMessage, OutgoingMessage } from 'http';
import type {
  GetServerSideProps,
  GetServerSidePropsContext,
  GetServerSidePropsResult,
  PreviewData,
  NextApiHandler,
  NextApiRequest,
  NextApiResponse,
} from 'next';
import type { ParsedUrlQuery } from 'querystring';

import { Fief, FiefAccessTokenInfo, FiefUserInfo } from '../client';
import {
  AuthenticateRequestParameters,
  AuthenticateRequestResult,
  FiefAuth as FiefAuthServer,
  FiefAuthForbidden,
  FiefAuthUnauthorized,
  IUserInfoCache,
  TokenGetter,
} from '../server';

const getServerSidePropsResultIsProps = <P>(result: GetServerSidePropsResult<P>): result is { props: P | Promise<P> } => Object.prototype.hasOwnProperty.call(result, 'props');

const defaultUnauthorizedResponse = async (req: NextApiRequest, res: NextApiResponse) => {
  res.status(401).send('Unauthorized');
};

const defaultForbiddenResponse = async (req: NextApiRequest, res: NextApiResponse) => {
  res.status(403).send('Forbidden');
};

type FiefNextApiHandler<T> = (
  req: NextApiRequest & AuthenticateRequestResult,
  res: NextApiResponse<T>,
) => unknown | Promise<unknown>;

interface FiefAuthParameters {
  client: Fief;
  tokenGetter: TokenGetter<IncomingMessage>;
  userInfoCache?: IUserInfoCache<IncomingMessage, OutgoingMessage>;
  redirectURI: string;
  unauthorizedResponse?: (req: IncomingMessage, res: OutgoingMessage) => Promise<void>;
  forbiddenResponse?: (req: IncomingMessage, res: OutgoingMessage) => Promise<void>;
}

export class FiefAuth {
  private client: Fief;

  private fiefAuth: FiefAuthServer<IncomingMessage, OutgoingMessage>;

  private redirectURI: string;

  private unauthorizedResponse: (req: NextApiRequest, res: NextApiResponse) => Promise<void>;

  private forbiddenResponse: (req: NextApiRequest, res: NextApiResponse) => Promise<void>;

  constructor(parameters: FiefAuthParameters) {
    this.client = parameters.client;
    this.fiefAuth = new FiefAuthServer<IncomingMessage, OutgoingMessage>(
      parameters.client,
      parameters.tokenGetter,
      parameters.userInfoCache,
    );
    this.redirectURI = parameters.redirectURI;
    this.unauthorizedResponse = parameters.unauthorizedResponse
      ? parameters.unauthorizedResponse
      : defaultUnauthorizedResponse
    ;
    this.forbiddenResponse = parameters.forbiddenResponse
      ? parameters.forbiddenResponse
      : defaultForbiddenResponse
    ;
  }

  public withAuth<
    P extends { [key: string]: any } = { [key: string]: any },
    Q extends ParsedUrlQuery = ParsedUrlQuery,
    D extends PreviewData = PreviewData,
  >(
    getServerSideProps: GetServerSideProps<P, Q, D>,
    authenticatedParameters: AuthenticateRequestParameters = {},
  ) {
    const authenticate = this.fiefAuth.authenticate(authenticatedParameters);
    return async (
      context: GetServerSidePropsContext<Q, D>,
      // eslint-disable-next-line max-len
    ): Promise<GetServerSidePropsResult<P & AuthenticateRequestResult & { forbidden: boolean }>> => {
      const { req, res } = context;
      let user: FiefUserInfo | null = null;
      let accessTokenInfo: FiefAccessTokenInfo | null = null;
      let forbidden = false;
      try {
        const result = await authenticate(req, res);
        user = result.user;
        accessTokenInfo = result.accessTokenInfo;
      } catch (err) {
        if (err instanceof FiefAuthUnauthorized) {
          const authURL = await this.client.getAuthURL({ redirectURI: this.redirectURI, scope: ['openid'] });
          return {
            redirect: {
              destination: authURL,
              permanent: false,
            },
          };
        }
        if (err instanceof FiefAuthForbidden) {
          forbidden = true;
        }
      }

      const result = await getServerSideProps(context);
      if (getServerSidePropsResultIsProps(result)) {
        if (result.props instanceof Promise) {
          return {
            ...result,
            props: {
              ...(await result.props),
              accessTokenInfo,
              user,
              forbidden,
            },
          };
        }
        return {
          ...result,
          props: {
            ...result.props,
            accessTokenInfo,
            user,
            forbidden,
          },
        };
      }

      return result;
    };
  }

  public authenticated<T>(
    route: NextApiHandler<T>,
    authenticatedParameters: AuthenticateRequestParameters = {},
  ): FiefNextApiHandler<T> {
    const authenticate = this.fiefAuth.authenticate(authenticatedParameters);
    return async (req: NextApiRequest & AuthenticateRequestResult, res: NextApiResponse) => {
      let user: FiefUserInfo | null = null;
      let accessTokenInfo: FiefAccessTokenInfo | null = null;
      try {
        const result = await authenticate(req, res);
        user = result.user;
        accessTokenInfo = result.accessTokenInfo;
      } catch (err) {
        if (err instanceof FiefAuthUnauthorized) {
          return this.unauthorizedResponse(req, res);
        }
        if (err instanceof FiefAuthForbidden) {
          return this.forbiddenResponse(req, res);
        }
      }

      req.accessTokenInfo = accessTokenInfo;
      req.user = user;
      return route(req, res);
    };
  }
}
