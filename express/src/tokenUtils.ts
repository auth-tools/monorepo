import { sign, verify } from "jsonwebtoken";
import { PassedProps, UserData } from "./authInstance";
import { NextFunction, Request, Response } from "express";
import { sendAuthError } from "./senders";

//payload of the token based on UserData type
//id only, because username and email could change
export type TokenPayload = Pick<UserData, "id">;

//generare an access- or refreshToken
export function generateToken(
  payload: TokenPayload,
  secret: string,
  expiresIn?: number
) {
  //gemerate (sign) a token with the payload from secret
  return sign(
    payload,
    secret,
    //add expiresIn flag when given (only used for accessTokens)
    expiresIn ? { expiresIn: expiresIn } : undefined
  );
}

//decode the payload of a token (also verify it is not modified)
export function decodeToken(
  token: string,
  secret: string
): { valid: boolean; payload: TokenPayload | null } {
  try {
    //decrypt the token with secret
    const data = verify(token, secret) as TokenPayload;
    return { valid: true, payload: { id: data.id } };
  } catch {
    //return unvalid, when token decryption failed
    return { valid: false, payload: null };
  }
}

//create validation function for access tokens that has access to props of AuthInstance class
export function createAccessTokenValidation(props: PassedProps) {
  return function (accessToken?: string): {
    tokenError: boolean;
    code: number;
    payload: TokenPayload | null;
  } {
    //error when access token is not passed by user
    if (!accessToken) {
      props.log("debug", "ACCESSTOKEN MISSING");
      return { tokenError: true, code: 1, payload: null };
    }

    //try decoding access token
    const { valid, payload } = decodeToken(
      accessToken,
      props.config.accessTokenSecret
    );

    //error if access token is invalid
    if (!valid || !payload) {
      props.log("debug", "THE ACCESSTOKEN IS INVALID");
      return { tokenError: true, code: 2, payload: null };
    }

    //pass that token is valid
    return { tokenError: false, code: 0, payload: payload };
  };
}

//locals that are added to res.locals in AuthInstance.validateAuthMiddleware
export type AuthResponseLocals = { payload: TokenPayload };

//factory for AuthInstance.validateAuthMiddleware
export function createAccessTokenValidationMiddleware(props: PassedProps) {
  return (req: Request, res: Response, next: NextFunction) => {
    //get token from authorization header
    const authHeader = req.get("authorization");
    const token = authHeader && authHeader.split(" ")[1];

    //create access token validation
    const validate = createAccessTokenValidation(props);

    //validate the access token
    const { tokenError, code, payload } = validate(token);

    //error when access token is not passed by user
    if (tokenError && code === 1) return sendAuthError(res, 400, code);

    //error if access token is invalid
    if (tokenError && code === 2) return sendAuthError(res, 403, code);

    res.locals.payload = payload;

    next();
  };
}
