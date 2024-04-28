import { RequestHandler } from "express";
import { PassedProps } from "../authInstance";
import { sendAuthError, sendAuthResponse, sendAuthServerError } from "../senders";
import { decodeToken, generateToken } from "../tokenUtils";

export default function ({
  config,
  log,
  useEventCallbacks,
  interceptEventCallbacks,
}: PassedProps): RequestHandler {
  return async function (req, res) {
    //check if logout refresh is disabled
    if (config.routes.refresh === "disabled") {
      log("debug", "REFRESH ROUTE DISABLED");
      return sendAuthError(res, 403, 41);
    }

    try {
      const { refreshToken }: { refreshToken: string } = req.body;

      if (!refreshToken) {
        log("debug", "REFRESHTOKEN MISSING");
        return sendAuthError(res, 400, 42);
      }

      const { valid, payload } = decodeToken(
        refreshToken,
        config.refreshTokenSecret
      );

      if (!valid || !payload) {
        log("debug", "THE REFRESHTOKEN IS INVALID");
        return sendAuthError(res, 403, 43);
      }

      const { serverError: checkTokenServerError, exists } =
        await useEventCallbacks.checkToken({ token: refreshToken });

      if (checkTokenServerError) return sendAuthServerError(res);

      if (!exists) {
        log("debug", "THE REFRESHTOKEN DOES NOT EXIST");
        return sendAuthError(res, 404, 44);
      }

      const accessToken = generateToken(
        { id: payload.id },
        config.accessTokenSecret,
        config.expiresIn
      );

      return sendAuthResponse(res, 201, )
    } catch (error) {
      log("warn", String(error));
      return sendAuthServerError(res);
    }
  };
}
