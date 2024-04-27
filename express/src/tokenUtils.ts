import { sign, verify } from "jsonwebtoken";
import { PassedProps, UserData } from "./authInstance";
import { NextFunction, Request, Response } from "express";
import { sendAuthError } from "./senders";

export type TokenPayload = Pick<UserData, "id">;

export function generateToken(
  payload: TokenPayload,
  secret: string,
  expiresIn?: number
) {
  return sign(
    payload,
    secret,
    expiresIn ? { expiresIn: expiresIn } : undefined
  );
}

export function decodeToken(
  token: string,
  secret: string
): { valid: boolean; payload: TokenPayload | null } {
  try {
    const data = verify(token, secret) as TokenPayload;
    return { valid: true, payload: data };
  } catch {
    return { valid: false, payload: null };
  }
}

export function createAccessTokenValidation(props: PassedProps) {
  return function (token?: string): {
    tokenError: boolean;
    code: number;
    payload: TokenPayload | null;
  } {
    if (!token) {
      // TODO fix messages
      props.log("debug", "ACCESSTOKEN MISSING");
      return { tokenError: true, code: 1, payload: null };
    }

    const { valid, payload } = decodeToken(
      token,
      props.config.accessTokenSecret
    );

    if (!valid || payload === null) {
      // TODO fix messages
      props.log("debug", "THE ACCESSTOKEN IS INVALID");
      return { tokenError: true, code: 2, payload: null };
    }

    return { tokenError: false, code: 0, payload: payload };
  };
}

export function createAccessTokenValidationMiddleware(props: PassedProps) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.get("authorization");
    const token = authHeader && authHeader.split(" ")[1];

    const validate = createAccessTokenValidation(props);

    const { tokenError, code, payload } = validate(token);

    if (tokenError && code === 1) return sendAuthError(res, 400, code);

    if (tokenError && code === 2) return sendAuthError(res, 403, code);

    res.locals.payload = payload;

    next();
  };
}
