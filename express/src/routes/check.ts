import { PassedProps } from "../authInstance";
import {
  sendAuthError,
  sendAuthResponse,
  sendAuthServerError,
} from "../senders";
import { decodeToken } from "../tokenUtils";
import { AuthRequestHandler } from "../router";

type RequestBody = { accessToken: string; refreshToken: string };

export default function ({
  config,
  log,
  useEventCallbacks,
  interceptEventCallbacks,
}: PassedProps): AuthRequestHandler<RequestBody> {
  return async function (req, res) {
    //check if check route is disabled
    if (config.routes.check === "disabled") {
      log("debug", "CHECK ROUTE DISABLED");
      return sendAuthError(res, 403, 51);
    }

    try {
      const { accessToken, refreshToken } = req.body;

      if (!accessToken || !refreshToken) {
        log("debug", "ACCESSTOKEN OR REFRESHTOKEN MISSING");
        return sendAuthError(res, 400, 52);
      }

      const { valid: refreshTokenValid, payload: refreshTokenPayload } =
        decodeToken(refreshToken, config.refreshTokenSecret);

      if (!refreshTokenValid || !refreshTokenPayload) {
        log("debug", "THE REFRESHTOKEN IS INVALID");
        return sendAuthError(res, 403, 53);
      }

      const { serverError: checkTokenServerError, exists } =
        await useEventCallbacks.checkToken({ refreshToken: refreshToken });

      if (checkTokenServerError) return sendAuthServerError(res);

      if (!exists) {
        log("debug", "THE REFRESHTOKEN DOES NOT EXIST");
        return sendAuthError(res, 404, 54);
      }

      const { valid: accessTokenValid } = decodeToken(
        accessToken,
        config.accessTokenSecret
      );

      if (!accessTokenValid) {
        log("debug", "THE ACCESSTOKEN IS INVALID");
        return sendAuthError(res, 403, 55);
      }

      const {
        serverError: interceptServerError,
        intercepted,
        interceptCode,
      } = await interceptEventCallbacks.check({
        accessToken: accessToken,
        refreshToken: refreshToken,
        payload: refreshTokenPayload,
      });

      if (interceptServerError) return sendAuthServerError(res);

      if (intercepted) return sendAuthError(res, 403, 59, interceptCode);

      return sendAuthResponse<null>(res, 200, 50, null);
    } catch (error) {
      log("warn", String(error));
      return sendAuthServerError(res);
    }
  };
}
