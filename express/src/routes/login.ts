import { RequestHandler } from "express";
import { PassedProps } from "../authInstance";
import {
  sendAuthError,
  sendAuthResponse,
  sendAuthServerError,
} from "../senders";
import getUserByLogin from "../getUserByLogin";
import { generateToken } from "../tokenUtils";

export default function ({
  config,
  log,
  useEventCallbacks,
  interceptEventCallbacks,
}: PassedProps): RequestHandler {
  return async function (req, res) {
    //check if login route is disabled
    if (config.routes.login === "disabled") {
      log("debug", "LOGIN ROUTE DISABLED");
      return sendAuthError(res, 403, 21);
    }

    try {
      const { login, password }: { login: string; password: string } = req.body;

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

      const {
        serverError: interceptServerError,
        intercepted,
        interceptCode,
      } = await interceptEventCallbacks.login({ user: user });

      if (interceptServerError) return sendAuthServerError(res);

      if (intercepted) return sendAuthError(res, 403, 29, interceptCode);

      const refreshToken = generateToken(
        { id: user.id },
        config.refreshTokenSecret
      );

      const accessToken = generateToken(
        { id: user.id },
        config.refreshTokenSecret,
        config.expiresIn
      );

      const { serverError: storeTokenServerError } =
        await useEventCallbacks.storeToken({
          token: refreshToken,
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
