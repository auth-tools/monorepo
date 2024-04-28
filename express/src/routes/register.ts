import { PassedProps, UserData } from "../authInstance";
import {
  sendAuthError,
  sendAuthResponse,
  sendAuthServerError,
} from "../senders";
import { parsePasswordRules } from "../inputValidation";
import getUserByLogin from "../getUserByLogin";
import { AuthRequestHandler } from "../router";

type RequestBody = { email: string; username: string; password: string };

export default function ({
  config,
  log,
  useEventCallbacks,
  interceptEventCallbacks,
}: PassedProps): AuthRequestHandler<RequestBody> {
  return async function (req, res) {
    //check if register route is disabled
    if (config.routes.register === "disabled") {
      log("debug", "REGISTER ROUTE DISABLED");
      return sendAuthError(res, 403, 11);
    }

    try {
      const { email, username, password } = req.body;

      if (!email || !username || !password) {
        log("debug", "EMAIL, USERNAME OR PASSWORD MISSING");
        return sendAuthError(res, 400, 12);
      }

      if (config.emailValidation) {
        const { serverError, isValid } = await useEventCallbacks.validateMail({
          email: email,
        });

        if (serverError) return sendAuthServerError(res);

        if (!isValid) {
          log("debug", "THE EMAIL IS MALFORMATED");
          return sendAuthError(res, 406, 13);
        }
      }

      if (config.passwordValidation) {
        const { serverError, isValid } =
          await useEventCallbacks.validatePassword({
            password: password,
            passwordRules: config.passwordValidationRules,
            parsedPasswordRules: parsePasswordRules(
              config.passwordValidationRules
            ),
          });

        if (serverError) return sendAuthServerError(res);

        if (!isValid) {
          log("debug", "THE PASSWORD IS TO WEAK");
          return sendAuthError(res, 406, 14);
        }
      }

      const { serverError: getUserByMailServerError, user: getUserByMailUser } =
        await getUserByLogin(res, email, useEventCallbacks);

      if (getUserByMailServerError) return sendAuthServerError(res);

      if (getUserByMailUser) {
        if (config.sensitiveLogs) log("debug", "THE LOGIN IS ALREDY USED");
        else log("debug", "THE EMAIL IS ALREDY USED");
        if (config.sensitiveApi) return sendAuthError(res, 403, 17);
        else return sendAuthError(res, 403, 15);
      }

      const { serverError: getUserByNameServerError, user: getUserByNameUser } =
        await getUserByLogin(res, username, useEventCallbacks);

      if (getUserByNameServerError) return sendAuthServerError(res);

      if (getUserByNameUser) {
        if (config.sensitiveLogs) log("debug", "THE LOGIN IS ALREDY USED");
        else log("debug", "THE USERNAME IS ALREDY USED");
        if (config.sensitiveApi) return sendAuthError(res, 403, 17);
        else return sendAuthError(res, 403, 16);
      }

      const { serverError: hashPasswordServerError, hashedPassword } =
        await useEventCallbacks.hashPassword({ password: password });

      if (hashPasswordServerError) return sendAuthServerError(res);

      const { serverError: genIdServerError, id } =
        await useEventCallbacks.genId({
          email: email,
          username: username,
        });

      if (genIdServerError) return sendAuthServerError(res);

      const user: UserData = {
        id: id,
        email: email,
        username: username,
        hashedPassword: hashedPassword,
      };

      const {
        serverError: interceptServerError,
        intercepted,
        interceptCode,
      } = await interceptEventCallbacks.register({
        user: user,
      });

      if (interceptServerError) return sendAuthServerError(res);

      if (intercepted) return sendAuthError(res, 403, 19, interceptCode);

      const { serverError: storeUserServerError } =
        await useEventCallbacks.storeUser({ user: user });

      if (storeUserServerError) return sendAuthServerError(res);

      return sendAuthResponse<Omit<UserData, "hashedPassword">>(res, 201, 10, {
        id: user.id,
        email: user.email,
        username: user.username,
      });
    } catch (error) {
      log("warn", String(error));
      return sendAuthServerError(res);
    }
  };
}
