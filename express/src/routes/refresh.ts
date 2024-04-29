import { PassedProps } from "../authInstance";
import {
  sendAuthError,
  sendAuthResponse,
  sendAuthServerError,
} from "../senders";
import { decodeToken, generateToken } from "../tokenUtils";
import { AuthRequestHandler } from "../router";

type RequestBody = { refreshToken: string };

export default function ({
  config,
  log,
  useEventCallbacks,
  interceptEventCallbacks,
}: PassedProps): AuthRequestHandler<RequestBody> {
  return async function (req, res) {
    //check if logout refresh is disabled
    if (config.routes.refresh === "disabled") {
      log("debug", "REFRESH ROUTE DISABLED");
      return sendAuthError(res, 403, 41);
    }

    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        log("debug", "REFRESHTOKEN MISSING");
        return sendAuthError(res, 400, 42);
      }

      const { valid: refreshTokenValid, payload: refreshTokenPayload } =
        decodeToken(refreshToken, config.refreshTokenSecret);

      if (!refreshTokenValid || !refreshTokenPayload) {
        log("debug", "THE REFRESHTOKEN IS INVALID");
        return sendAuthError(res, 403, 43);
      }

      const { serverError: checkTokenServerError, exists } =
        await useEventCallbacks.checkToken({ refreshToken: refreshToken });

      if (checkTokenServerError) return sendAuthServerError(res);

      if (!exists) {
        log("debug", "THE REFRESHTOKEN DOES NOT EXIST");
        return sendAuthError(res, 404, 44);
      }

      const {
        serverError: interceptServerError,
        intercepted,
        interceptCode,
      } = await interceptEventCallbacks.refresh({
        refreshToken: refreshToken,
        payload: refreshTokenPayload,
      });

      if (interceptServerError) return sendAuthServerError(res);

      if (intercepted) return sendAuthError(res, 403, 49, interceptCode);

      const accessToken = generateToken(
        { id: refreshTokenPayload.id },
        config.accessTokenSecret,
        config.expiresIn
      );

      return sendAuthResponse<{ accessToken: string }>(res, 201, 40, {
        accessToken: accessToken,
      });
    } catch (error) {
      log("warn", String(error));
      return sendAuthServerError(res);
    }
  };
}
