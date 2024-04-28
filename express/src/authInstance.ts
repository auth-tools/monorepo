import { RequestHandler, Router } from "express";
import { createAuthRouter } from "./router";
import {
  ParsedPasswordValidationRules,
  PasswordValidationRules,
  parsePasswordRules,
} from "./inputValidation";
import {
  defaultUseCheckPassword,
  defaultUseGenId,
  defaultUseHashPassword,
  defaultUseValidateMail,
  defaultUseValidatePassword,
  undefinedInterceptEvent,
  undefinedUseEvent,
} from "./events";
import {
  TokenPayload,
  createAccessTokenValidation,
  createAccessTokenValidationMiddleware,
} from "./tokenUtils";

type Promisify<Type> = Promise<Type> | Type;
type DeepRequired<T> = { [K in keyof T]-?: DeepRequired<T[K]> };

type RouteState = "active" | "disabled" | "removed";

export type AuthConfig = {
  accessTokenSecret: string;
  refreshTokenSecret: string;
  expiresIn?: number;
  passwordValidation?: boolean;
  passwordValidationRules?: PasswordValidationRules;
  emailValidation?: boolean;
  sensitiveApi?: boolean;
  sensitiveLogs?: boolean;
  routes?: {
    register?: RouteState;
    login?: RouteState;
    logout?: RouteState;
    refresh?: RouteState;
    check?: RouteState;
  };
};

export type RequiredAuthConfig = DeepRequired<AuthConfig>;

export type PassedProps = {
  config: RequiredAuthConfig;
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

type UseEvent<Data, Return = {}> = {
  data: Data;
  return: { serverError?: boolean } & Return;
};
export type UseEvents = {
  //required useEvents
  getUserByMail: UseEvent<{ email: string }, { user: UserData | null }>;
  getUserByName: UseEvent<{ username: string }, { user: UserData | null }>;
  hashPassword: UseEvent<{ password: string }, { hashedPassword: string }>;
  checkToken: UseEvent<{ token: string }, { exists: boolean }>;
  storeToken: UseEvent<{ token: string }>;
  deleteToken: UseEvent<{ token: string }>;
  //optional useEvents
  validateMail: UseEvent<{ email: string }, { isValid: boolean }>;
  validatePassword: UseEvent<
    {
      password: string;
      passwordRules: PasswordValidationRules;
      parsedPasswordRules: ParsedPasswordValidationRules;
    },
    { isValid: boolean }
  >;
  genId: UseEvent<{ username: string; email: string }, { id: string }>;
  storeUser: UseEvent<{ user: UserData }>;
  checkPassword: UseEvent<
    { password: string; hashedPassword: string },
    { matches: boolean }
  >;
};
export type UseEventCallback<Type extends keyof UseEvents> = (
  data: UseEvents[Type]["data"]
) => Promisify<UseEvents[Type]["return"]>;
export type UseEventCallbacks = {
  [Key in keyof UseEvents]: UseEventCallback<Key>;
};

type InterceptEvent<Data> = {
  data: Data;
  return: { serverError?: number; intercepted: boolean; interceptCode: number };
};
export type InterceptEvents = {
  register: InterceptEvent<{ user: UserData }>;
  login: InterceptEvent<{ user: UserData }>;
  logout: InterceptEvent<{ payload: TokenPayload; token: string }>;
  refresh: InterceptEvent<{ payload: TokenPayload; token: string }>;
  check: InterceptEvent<{ payload: TokenPayload; token: string }>;
};
export type InterceptEventCallback<Type extends keyof InterceptEvents> = (
  data: InterceptEvents[Type]["data"]
) => Promisify<InterceptEvents[Type]["return"]>;
type InterceptEventCallbacks = {
  [Key in keyof InterceptEvents]: InterceptEventCallback<Key>;
};

export class AuthInstance {
  public logFunction: LogFunction = console.log;
  public router: Router;
  private useEventCallbacks: UseEventCallbacks = {
    getUserByMail: undefinedUseEvent(
      "getUserByMail",
      {
        user: null,
      },
      this.logFunction
    ),
    getUserByName: undefinedUseEvent(
      "getUserByName",
      {
        user: null,
      },
      this.logFunction
    ),
    storeUser: undefinedUseEvent("storeUser", {}, this.logFunction),
    checkToken: undefinedUseEvent(
      "checkToken",
      {
        exists: false,
      },
      this.logFunction
    ),
    storeToken: undefinedUseEvent("storeToken", {}, this.logFunction),
    deleteToken: undefinedUseEvent("deleteToken", {}, this.logFunction),
    validateMail: defaultUseValidateMail(),
    validatePassword: defaultUseValidatePassword(),
    hashPassword: defaultUseHashPassword(this.logFunction),
    genId: defaultUseGenId(),
    checkPassword: defaultUseCheckPassword(this.logFunction),
  };
  private interceptEventCallbacks: InterceptEventCallbacks = {
    register: undefinedInterceptEvent(),
    login: undefinedInterceptEvent(),
    logout: undefinedInterceptEvent(),
    refresh: undefinedInterceptEvent(),
    check: undefinedInterceptEvent(),
  };
  public validateAuth: (
    token?: string
  ) => ReturnType<ReturnType<typeof createAccessTokenValidation>>;
  public validateAuthMiddleware: RequestHandler;
  public validateEmail: (
    email: string
  ) => Promise<UseEvents["validateMail"]["return"]>;
  public validatePassword: (
    password: string
  ) => Promise<UseEvents["validatePassword"]["return"]>;

  constructor(config: AuthConfig) {
    //create the props to pass to handlers with defaults
    const passedProps: PassedProps = {
      config: {
        accessTokenSecret: config.accessTokenSecret,
        refreshTokenSecret: config.refreshTokenSecret,
        expiresIn: config.expiresIn ?? 900,
        passwordValidation: config.passwordValidation ?? true,
        passwordValidationRules: config.passwordValidationRules ?? "Y-Y-Y-N-8",
        emailValidation: config.emailValidation ?? true,
        sensitiveApi: config.sensitiveApi ?? true,
        sensitiveLogs: config.sensitiveLogs ?? false,
        routes: {
          register: config.routes?.register ?? "active",
          login: config.routes?.login ?? "active",
          logout: config.routes?.logout ?? "active",
          refresh: config.routes?.refresh ?? "active",
          check: config.routes?.check ?? "active",
        },
      },
      useEventCallbacks: this.useEventCallbacks,
      interceptEventCallbacks: this.interceptEventCallbacks,
      log: this.logFunction,
    };

    this.router = createAuthRouter(passedProps);

    this.validateAuth = createAccessTokenValidation(passedProps);

    this.validateAuthMiddleware =
      createAccessTokenValidationMiddleware(passedProps);

    this.validateEmail = async (email) => {
      return await this.useEventCallbacks.validateMail({ email: email });
    };

    this.validatePassword = async (password) => {
      return await this.useEventCallbacks.validatePassword({
        password: password,
        passwordRules: passedProps.config.passwordValidationRules,
        parsedPasswordRules: parsePasswordRules(
          passedProps.config.passwordValidationRules
        ),
      });
    };
  }

  //function to set the logfunction to a user given function
  public log(logFunction: LogFunction) {
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
