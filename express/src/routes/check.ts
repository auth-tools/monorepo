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
    //check if check route is disabled
    if (config.routes.check === "disabled") {
      log("debug", "CHECK ROUTE DISABLED");
      return sendAuthError(res, 403, 51);
    }

    try {
      // CODE HERE
    } catch (error) {
      log("warn", String(error));
      return sendAuthServerError(res);
    }
  };
}
