import { PassedProps } from "../authInstance";
import {
  sendAuthError,
  sendAuthResponse,
  sendAuthServerError,
} from "../senders";
import { decodeToken } from "../tokenUtils";
import { AuthRequestHandler } from "../router";

type RequestBody = { refreshToken: string };

export default function ({
  config,
  log,
  useEventCallbacks,
  interceptEventCallbacks,
}: PassedProps): AuthRequestHandler<RequestBody> {
  return async function (req, res) {
    //check if logout route is disabled
    if (config.routes.logout === "disabled") {
      log("debug", "LOGOUT ROUTE DISABLED");
      return sendAuthError(res, 403, 31);
    }

    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        log("debug", "REFRESHTOKEN MISSING");
        return sendAuthError(res, 400, 32);
      }

      const { valid: refreshTokenValid, payload: refreshTokenPayload } =
        decodeToken(refreshToken, config.refreshTokenSecret);

      if (!refreshTokenValid || !refreshTokenPayload) {
        log("debug", "THE REFRESHTOKEN IS INVALID");
        return sendAuthError(res, 403, 33);
      }

      const { serverError: checkTokenServerError, exists } =
        await useEventCallbacks.checkToken({ refreshToken: refreshToken });

      if (checkTokenServerError) return sendAuthServerError(res);

      if (!exists) {
        log("debug", "THE REFRESHTOKEN DOES NOT EXIST");
        return sendAuthError(res, 404, 34);
      }

      const {
        serverError: interceptServerError,
        intercepted,
        interceptCode,
      } = await interceptEventCallbacks.logout({
        refreshToken: refreshToken,
        payload: refreshTokenPayload,
      });

      if (interceptServerError) return sendAuthServerError(res);

      if (intercepted) return sendAuthError(res, 403, 39, interceptCode);

      const { serverError: deleteTokenServerError } =
        await useEventCallbacks.deleteToken({
          refreshToken: refreshToken,
        });

      if (deleteTokenServerError) return sendAuthServerError(res);

      return sendAuthResponse<null>(res, 200, 10, null);
    } catch (error) {
      log("warn", String(error));
      return sendAuthServerError(res);
    }
  };
}
