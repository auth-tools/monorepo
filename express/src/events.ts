import { v4 } from "uuid";
import {
  InterceptEventCallback,
  InterceptEvents,
  LogFunction,
  UseEventCallback,
  UseEvents,
} from "./authInstance";
import { validateEmail, validatePassword } from "./inputValidation";
import { compare, hash } from "bcrypt";

//function to error out and complain if an use event is undefined when it is ran
export function undefinedUseEvent<
  Event extends keyof UseEvents,
  Return extends UseEvents[Event]["return"]
>(event: Event, returnData: Return, log: LogFunction): UseEventCallback<Event> {
  return () => {
    //complain about unset use event callback
    log("error", `NEEDED USE ${event} EVENT IS UNDEFINED`);
    return { ...returnData, serverError: true };
  };
}

//default use event for hashPassword
export function defaultUseHashPassword(
  log: LogFunction
): UseEventCallback<"hashPassword"> {
  return async ({ password }) => {
    try {
      const hashedPassword = await hash(password, 10);
      return { hashedPassword: hashedPassword };
    } catch (error) {
      log("warn", String(error));
      return { serverError: true, hashedPassword: "" };
    }
  };
}

//default use event for genId
export function defaultUseGenId(): UseEventCallback<"genId"> {
  return () => {
    return { id: v4() };
  };
}

//default use event for checkPassword
export function defaultUseCheckPassword(
  log: LogFunction
): UseEventCallback<"checkPassword"> {
  return async ({ password, hashedPassword }) => {
    try {
      const matches = await compare(password, hashedPassword);
      return { matches: matches };
    } catch (error) {
      log("warn", String(error));
      return { serverError: true, matches: false };
    }
  };
}

//default use event for validateMail
export function defaultUseValidateMail(): UseEventCallback<"validateMail"> {
  return ({ email }) => {
    return { isValid: validateEmail(email) };
  };
}

//default use event for validatePassword
export function defaultUseValidatePassword(): UseEventCallback<"validatePassword"> {
  return ({ password, passwordRules }) => {
    return { isValid: validatePassword(password, passwordRules) };
  };
}

//function to error out and complain if an intercept event is undefined when it is ran
export function undefinedInterceptEvent<
  Event extends keyof InterceptEvents
>(): InterceptEventCallback<Event> {
  return () => {
    return { intercepted: false, interceptCode: 0 };
  };
}
