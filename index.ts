import {AppError, type TContext, type TMiddleware} from "@utf8pro/app"
import {createJwt, type TJwtPayload} from "@utf8pro/jwt"

type TPayload = {
  uid: string
} & TJwtPayload;

const tokenKey = process.env.TOKEN_KEY || "some_secret_token"
const tokenIssuer = process.env.TOKEN_ISSUER || "utf8.pro"
const jwt = createJwt(tokenKey)

export type TCreateAuthMiddlewareParams = {
  excludePaths?: string[]
}

const createAuthMiddlewareDefaultParams = {
  excludePaths: [],
}

export function createAuthMiddleware(options: TCreateAuthMiddlewareParams): TMiddleware {
  const {excludePaths} = {
    ...createAuthMiddlewareDefaultParams,
    ...options,
  }
  return async ({request, pathname, params}: TContext): Promise<void> => {
    if (excludePaths.includes(pathname)) {
      return
    }
    const authHeader = request.headers.get("Authorization")
    if (!authHeader) {
      throw new AuthError("Authorization header required")
    }
    try {
      const {uid} = await jwt.verify<TPayload>(authHeader)
      params.authorizedAccountId = uid.toString()
    } catch (err) {
      throw new AuthError(`Invalid Jwt token`)
    }
  }
}

export async function createToken(accountId: bigint): Promise<string> {
  return await jwt.sign<TPayload>({
    exp: getExp(),
    uid: accountId.toString(),
    iss: tokenIssuer,
  })
}

export class AuthError extends AppError {
  constructor(message: string) {
    super(message, 401)
  }
}

function getExp(): number {
  return Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 365) // one year from now
}
