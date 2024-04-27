import { Response } from "express";
import { UseEventCallbacks, UserData } from "./authInstance";
import { sendAuthServerError } from "./senders";

export default async function (
  res: Response,
  login: string,
  useEventCallbacks: UseEventCallbacks
): Promise<{ serverError: boolean; user: UserData | null }> {
  const { serverError: serverErrorByMail, user: userByMail } =
    await useEventCallbacks.getUserByMail({
      email: login,
    });

  if (serverErrorByMail) {
    sendAuthServerError(res);
    return { serverError: true, user: null };
  }

  const { serverError: serverErrorByName, user: userByName } =
    await useEventCallbacks.getUserByName({
      username: login,
    });

  if (serverErrorByName) {
    sendAuthServerError(res);
    return { serverError: true, user: null };
  }

  return { serverError: false, user: userByMail || userByName };
}
