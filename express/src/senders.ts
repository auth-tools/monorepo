import { Response } from "express";

//standard auth response from authentication server
type AuthResponse = {
  error: boolean;
  code: number;
  interceptCode: number;
};

//base function with all parameters
function sendAuthData<ResponseData>(
  res: Response<{ auth: AuthResponse; data: ResponseData }>,
  httpCode: number,
  auth: AuthResponse,
  data: ResponseData
) {
  //create response with http status code
  return res.status(httpCode).json({ auth: auth, data: data });
}

//auth response shorthand sender
export function sendAuthResponse<ResponseData>(
  res: Response,
  httpCode: number,
  authCode: number,
  data: ResponseData
) {
  return sendAuthData(
    res,
    httpCode,
    { error: false, code: authCode, interceptCode: 0 },
    data
  );
}

//auth error shorthand sender
export function sendAuthError(
  res: Response,
  httpCode: number,
  authCode: number,
  interceptCode: number = 0
) {
  return sendAuthData(
    res,
    httpCode,
    { error: true, code: authCode, interceptCode: interceptCode },
    null
  );
}

//auth server error shorthand sender
export function sendAuthServerError(res: Response) {
  return sendAuthError(res, 500, 5);
}

//sender with successfull auth
export function sendData<ResponseData>(
  res: Response,
  httpCode: number,
  data: ResponseData
) {
  return sendAuthData(
    res,
    httpCode,
    { error: false, code: 0, interceptCode: 0 },
    data
  );
}
