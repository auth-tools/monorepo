import { Response } from "express";
import { UseEventCallbacks, UserData } from "./authInstance";
import { sendAuthServerError } from "./senders";

//explination: This function is here, so in further steps userB can't set his email to userA's username. -> This helps that users have a clear identity

//gets a user that has value of "login" as email OR as username
export default async function (
  res: Response,
  login: string,
  useEventCallbacks: UseEventCallbacks
): Promise<{ serverError: boolean; user: UserData | null }> {
  //get user by email with value of login
  const { serverError: serverErrorByMail, user: userByMail } =
    await useEventCallbacks.getUserByMail({
      email: login,
    });

  //send server error (500) when getUserByMail errored
  if (serverErrorByMail) {
    sendAuthServerError(res);
    return { serverError: true, user: null };
  }

  //get user by username with value of login
  const { serverError: serverErrorByName, user: userByName } =
    await useEventCallbacks.getUserByName({
      username: login,
    });

  //send server error (500) when getUserByName errored
  if (serverErrorByName) {
    sendAuthServerError(res);
    return { serverError: true, user: null };
  }

  //return a found user when a user was found else return null
  return { serverError: false, user: userByMail || userByName };
}
