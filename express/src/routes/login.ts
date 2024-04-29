import { PassedProps } from "../authInstance";
import {
  sendAuthError,
  sendAuthResponse,
  sendAuthServerError,
} from "../senders";
import getUserByLogin from "../getUserByLogin";
import { TokenPayload, generateToken } from "../tokenUtils";
import { AuthRequestHandler } from "../router";

type RequestBody = { login: string; password: string };

export default function ({
  config,
  log,
  useEventCallbacks,
  interceptEventCallbacks,
}: PassedProps): AuthRequestHandler<RequestBody> {
  return async function (req, res) {
    //check if login route is disabled
    if (config.routes.login === "disabled") {
      log("debug", "LOGIN ROUTE DISABLED");
      return sendAuthError(res, 403, 21);
    }

    try {
      const { login, password } = req.body;

      if (!login || !password) {
        log("debug", "LOGIN OR PASSWORD MISSING");
        return sendAuthError(res, 400, 22);
      }
      const { serverError: getUserByLoginServerError, user } =
        await getUserByLogin(res, login, useEventCallbacks);

      if (getUserByLoginServerError) return sendAuthServerError(res);

      if (!user) {
        if (config.sensitiveLogs)
          log("debug", "USER WAS NOT FOUND OR PASSWORD IS INCORRECT");
        else log("debug", "USER WAS NOT FOUND");
        if (config.sensitiveApi) return sendAuthError(res, 403, 25);
        else return sendAuthError(res, 403, 23);
      }

      const { serverError: checkPasswordServerError, matches } =
        await useEventCallbacks.checkPassword({
          password: password,
          hashedPassword: user.hashedPassword,
        });

      if (checkPasswordServerError) return sendAuthServerError(res);

      if (!matches) {
        if (config.sensitiveLogs)
          log("debug", "USER WAS NOT FOUND OR PASSWORD IS INCORRECT");
        else log("debug", "PASSWORD IS INCORRECT");
        if (config.sensitiveApi) return sendAuthError(res, 403, 25);
        else return sendAuthError(res, 403, 24);
      }

      const payload: TokenPayload = { id: user.id };

      const refreshToken = generateToken(payload, config.refreshTokenSecret);

      const accessToken = generateToken(
        payload,
        config.accessTokenSecret,
        config.expiresIn
      );

      const {
        serverError: interceptServerError,
        intercepted,
        interceptCode,
      } = await interceptEventCallbacks.login({
        user: user,
        accessToken: accessToken,
        refreshToken: refreshToken,
        payload: payload,
      });

      if (interceptServerError) return sendAuthServerError(res);

      if (intercepted) return sendAuthError(res, 403, 29, interceptCode);

      const { serverError: storeTokenServerError } =
        await useEventCallbacks.storeToken({
          refreshToken: refreshToken,
        });

      if (storeTokenServerError) return sendAuthServerError(res);

      return sendAuthResponse<{ accessToken: string; refreshToken: string }>(
        res,
        201,
        20,
        { accessToken: accessToken, refreshToken: refreshToken }
      );
    } catch (error) {
      log("warn", String(error));
      return sendAuthServerError(res);
    }
  };
}
