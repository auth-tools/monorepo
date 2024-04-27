import { RequestHandler } from "express";
import { PassedProps } from "../authInstance";
import { sendAuthError, sendAuthServerError } from "../senders";

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
      // CODE HERE
    } catch (error) {
      log("warn", String(error));
      return sendAuthServerError(res);
    }
  };
}
