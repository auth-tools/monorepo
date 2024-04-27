import { RequestHandler, Router } from "express";
import { createAuthRouter } from "./router";
import { PasswordValidationRules } from "./validation";

type Promisify<Type> = Promise<Type> | Type;
type DeepRequired<T> = { [K in keyof T]-?: DeepRequired<T[K]> };

export type AuthConfig = {
  accessTokenSecret: string;
  refreshTokenSecret: string;
  expiresIn?: number;
  passwordValidation?: PasswordValidationRules;
  emailValidation?: boolean;
  routes?: {
    register?: boolean;
    login?: boolean;
    logout?: boolean;
    refresh?: boolean;
    check?: boolean;
  };
};

export type PassedProps = {
  config: DeepRequired<AuthConfig>;
  useEventCallbacks: UseEventCallbacks;
  interceptEventCallbacks: InterceptEventCallbacks;
  log: LogFunction;
};

export type LogLevels = "debug" | "info" | "warn" | "error";
export type LogFunction = (level: LogLevels, data: string) => void;

export type UserData = {
  id: string;
  email: string;
  username: string;
  hashedPassword: string;
};
export type TokenPayload = Pick<UserData, "id">;

type UseEvent<Data, Return = {}> = {
  data: Data;
  return: { err: boolean } & Return;
};
type UseEvents = {
  getUserByMail: UseEvent<{ email: string }, { user: UserData | null }>;
  getUserByName: UseEvent<{ username: string }, { user: UserData | null }>;
  storeUser: UseEvent<{ user: UserData }>;
  checkToken: UseEvent<{ token: string }, { exists: boolean }>;
  storeToken: UseEvent<{ token: string }>;
  deleteToken: UseEvent<{ token: string }>;
};
type UseEventCallback<Type extends keyof UseEvents> = (
  data: UseEvents[Type]["data"]
) => Promisify<UseEvents[Type]["return"]>;
type UseEventCallbacks = { [Key in keyof UseEvents]: UseEventCallback<Key> };

type InterceptEvent<Data> = {
  data: Data;
  return: { err: boolean; code: number };
};
type InterceptEvents = {
  register: InterceptEvent<{ user: UserData }>;
  login: InterceptEvent<{ user: UserData }>;
  logout: InterceptEvent<{}>;
  refresh: InterceptEvent<{}>;
  check: InterceptEvent<{}>;
};
type InterceptEventCallback<Type extends keyof InterceptEvents> = (
  data: InterceptEvents[Type]["data"]
) => Promisify<InterceptEvents[Type]["return"]>;
type InterceptEventCallbacks = {
  [Key in keyof InterceptEvents]: InterceptEventCallback<Key>;
};

export class AuthInstance {
  public logFunction: LogFunction = console.log;
  public router: Router;
  private useEventCallbacks: UseEventCallbacks = {
    getUserByMail: this.undefinedUseEvent("getUserByMail", {
      err: true,
      user: null,
    }),
    getUserByName: this.undefinedUseEvent("getUserByName", {
      err: true,
      user: null,
    }),
    storeUser: this.undefinedUseEvent("storeUser", { err: true }),
    checkToken: this.undefinedUseEvent("checkToken", {
      err: true,
      exists: false,
    }),
    storeToken: this.undefinedUseEvent("storeToken", { err: true }),
    deleteToken: this.undefinedUseEvent("deleteToken", { err: true }),
  };
  private interceptEventCallbacks: InterceptEventCallbacks = {
    register: this.undefinedInterceptEvent(),
    login: this.undefinedInterceptEvent(),
    logout: this.undefinedInterceptEvent(),
    refresh: this.undefinedInterceptEvent(),
    check: this.undefinedInterceptEvent(),
  };
  // public validateAuth:
  // public validateAuthMiddleware: RequestHandler;

  constructor(config: AuthConfig) {
    //create the props to pass to handlers with defaults
    const passedProps: PassedProps = {
      config: {
        accessTokenSecret: config.accessTokenSecret,
        refreshTokenSecret: config.refreshTokenSecret,
        expiresIn: config.expiresIn ?? 900,
        passwordValidation: config.passwordValidation ?? "Y-Y-Y-N-8",
        emailValidation: config.emailValidation ?? true,
        routes: {
          register: config.routes?.register ?? true,
          login: config.routes?.login ?? true,
          logout: config.routes?.logout ?? true,
          refresh: config.routes?.refresh ?? true,
          check: config.routes?.check ?? true,
        },
      },
      useEventCallbacks: this.useEventCallbacks,
      interceptEventCallbacks: this.interceptEventCallbacks,
      log: this.logFunction,
    };

    //create Router
    this.router = createAuthRouter(passedProps);
  }

  //function to error out and complain if an use event is undefined when it is ran
  private undefinedUseEvent<
    Event extends keyof UseEvents,
    Return extends UseEvents[Event]["return"]
  >(event: Event, returnData: Return): UseEventCallback<Event> {
    return () => {
      //complain about unset use event callback
      this.logFunction(
        "error",
        `The "use" event "${event}" was ran but is not set!`
      );
      return returnData;
    };
  }

  //function to error out and complain if an intercept event is undefined when it is ran
  private undefinedInterceptEvent<
    Event extends keyof InterceptEvents
  >(): InterceptEventCallback<Event> {
    return () => {
      return { err: false, code: 0 };
    };
  }

  //function to set the logfunction to a user given function
  public async log(logFunction: LogFunction) {
    this.logFunction = logFunction;
  }

  //function to set the use callback to an event with a given function
  public use<Type extends keyof UseEvents>(
    event: Type,
    callback: UseEventCallback<Type>
  ): void {
    //set use event callback
    (this.useEventCallbacks[event] as UseEventCallback<Type>) = callback;
  }

  //function to set the intercept callback to an event with a given function
  public intercept<Type extends keyof InterceptEvents>(
    event: Type,
    callback: InterceptEventCallback<Type>
  ): void {
    //set intercept event callback
    (this.interceptEventCallbacks[event] as InterceptEventCallback<Type>) =
      callback;
  }
}
