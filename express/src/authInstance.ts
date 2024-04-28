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

//util types
type Promisify<Type> = Promise<Type> | Type;
type DeepRequired<T> = { [K in keyof T]-?: DeepRequired<T[K]> };

//states of a route
type RouteState = "active" | "disabled" | "removed";

//config passed by user to class
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

//config with all values as required
export type RequiredAuthConfig = DeepRequired<AuthConfig>;

//all props of the class that are passed to functions
export type PassedProps = {
  config: RequiredAuthConfig;
  useEventCallbacks: UseEventCallbacks;
  interceptEventCallbacks: InterceptEventCallbacks;
  log: LogFunction;
};

//definitions for logging function
export type LogLevels = "debug" | "info" | "warn" | "error";
export type LogFunction = (level: LogLevels, data: string) => any;

//userdata auth-tools uses for authentication
export type UserData = {
  id: string;
  email: string;
  username: string;
  hashedPassword: string;
};

//standard definition of a use event
type UseEvent<Data, Return = {}> = {
  data: Data;
  return: { serverError?: boolean } & Return;
};
//all use events
export type UseEvents = {
  //required useEvents
  getUserByMail: UseEvent<{ email: string }, { user: UserData | null }>;
  getUserByName: UseEvent<{ username: string }, { user: UserData | null }>;
  hashPassword: UseEvent<{ password: string }, { hashedPassword: string }>;
  checkToken: UseEvent<{ refreshToken: string }, { exists: boolean }>;
  storeToken: UseEvent<{ refreshToken: string }>;
  deleteToken: UseEvent<{ refreshToken: string }>;
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
//standard definition of a use event callback
export type UseEventCallback<Type extends keyof UseEvents> = (
  data: UseEvents[Type]["data"]
) => Promisify<UseEvents[Type]["return"]>;
//all use event callbacks
export type UseEventCallbacks = {
  [Key in keyof UseEvents]: UseEventCallback<Key>;
};

//standard definition of an incerpet event
type InterceptEvent<Data> = {
  data: Data;
  return: {
    serverError?: boolean;
    intercepted: boolean;
    interceptCode: number;
  };
};
//all intercept events
export type InterceptEvents = {
  register: InterceptEvent<{ user: UserData }>;
  login: InterceptEvent<{
    user: UserData;
    accessToken: string;
    refreshToken: string;
    payload: TokenPayload;
  }>;
  logout: InterceptEvent<{ refreshToken: string; payload: TokenPayload }>;
  refresh: InterceptEvent<{ refreshToken: string; payload: TokenPayload }>;
  check: InterceptEvent<{
    accessToken: string;
    refreshToken: string;
    payload: TokenPayload;
  }>;
};
//standard definition of an incerpet event callback
export type InterceptEventCallback<Type extends keyof InterceptEvents> = (
  data: InterceptEvents[Type]["data"]
) => Promisify<InterceptEvents[Type]["return"]>;
//all intercept event callbacks
type InterceptEventCallbacks = {
  [Key in keyof InterceptEvents]: InterceptEventCallback<Key>;
};

//authenticator class
export class AuthInstance {
  //authentication router with all routes
  public router: Router;

  //vars for all events
  private useEventCallbacks: UseEventCallbacks;
  private interceptEventCallbacks: InterceptEventCallbacks;

  //validate if a user is authenticated by his access token
  public validateAuth: (
    accessToken?: string
  ) => ReturnType<ReturnType<typeof createAccessTokenValidation>>;
  //validate if a user is authenticated by his access token as a express middleware
  public validateAuthMiddleware: RequestHandler;

  //validate given email with use event
  public validateEmail: (
    email: string
  ) => Promise<UseEvents["validateMail"]["return"]>;

  //validate given password with use event
  public validatePassword: (
    password: string
  ) => Promise<UseEvents["validatePassword"]["return"]>;

  //create auth class
  constructor(config: AuthConfig, log: LogFunction) {
    //defaults for use event callbacks
    this.useEventCallbacks = {
      //error functions for required events
      getUserByMail: undefinedUseEvent(
        "getUserByMail",
        {
          user: null,
        },
        log
      ),
      getUserByName: undefinedUseEvent(
        "getUserByName",
        {
          user: null,
        },
        log
      ),
      storeUser: undefinedUseEvent("storeUser", {}, log),
      checkToken: undefinedUseEvent(
        "checkToken",
        {
          exists: false,
        },
        log
      ),
      storeToken: undefinedUseEvent("storeToken", {}, log),
      deleteToken: undefinedUseEvent("deleteToken", {}, log),
      //defaults for optional events
      validateMail: defaultUseValidateMail(),
      validatePassword: defaultUseValidatePassword(),
      hashPassword: defaultUseHashPassword(log),
      genId: defaultUseGenId(),
      checkPassword: defaultUseCheckPassword(log),
    };

    //default (empty) intercept event callbacks
    this.interceptEventCallbacks = {
      register: undefinedInterceptEvent(),
      login: undefinedInterceptEvent(),
      logout: undefinedInterceptEvent(),
      refresh: undefinedInterceptEvent(),
      check: undefinedInterceptEvent(),
    };

    //create the props to pass to handlers with defaults
    const passedProps: PassedProps = {
      //all config defaults
      config: {
        accessTokenSecret: config.accessTokenSecret,
        refreshTokenSecret: config.refreshTokenSecret,
        expiresIn: config.expiresIn ?? 900, //by default accessToken expires in 900s (15min)
        passwordValidation: config.passwordValidation ?? true, //by default passwords are validated
        passwordValidationRules: config.passwordValidationRules ?? "Y-Y-Y-N-8", //by default when passwords are validated, they are validated with Y-Y-Y-N-8
        emailValidation: config.emailValidation ?? true, //by default emails are validated
        sensitiveApi: config.sensitiveApi ?? true, //by default api will not directly expose type of error which could leak information of the database
        sensitiveLogs: config.sensitiveLogs ?? false, //by default logs WILL directly expose type of error which could leak information of the database
        routes: {
          register: config.routes?.register ?? "active", //by default /register is active
          login: config.routes?.login ?? "active", //by default /login is active
          logout: config.routes?.logout ?? "active", //by default /logout is active
          refresh: config.routes?.refresh ?? "active", //by default /refresh is active
          check: config.routes?.check ?? "active", //by default /check is active
        },
      },
      //refrence to all use event callbacks
      useEventCallbacks: this.useEventCallbacks,
      //refrence to all intercept event callbacks
      interceptEventCallbacks: this.interceptEventCallbacks,
      //logging function
      log: log,
    };

    //creates the authentication express router (AuthInstance.router)
    this.router = createAuthRouter(passedProps);

    //creates the accessToken validation function (AuthInstance.validateAuth)
    this.validateAuth = createAccessTokenValidation(passedProps);

    //creates the accessToken validation express middleware (AuthInstance.validateAuthMiddleware)
    this.validateAuthMiddleware =
      createAccessTokenValidationMiddleware(passedProps);

    //creates the email validation function (AuthInstance.validateEmail)
    this.validateEmail = async (email) => {
      //runs use event validateMail to check if email is valid
      return await this.useEventCallbacks.validateMail({ email: email });
    };

    //creates the password validation function (AuthInstance.validatePassword)
    this.validatePassword = async (password) => {
      //runs use event validatePassword to check if password is valid
      return await this.useEventCallbacks.validatePassword({
        password: password,
        passwordRules: passedProps.config.passwordValidationRules,
        parsedPasswordRules: parsePasswordRules(
          passedProps.config.passwordValidationRules
        ),
      });
    };
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
