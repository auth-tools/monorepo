import AuthInstance, {
  AuthConfig,
  AuthResponseLocals,
  TokenPayload,
  UserData,
  sendData,
} from "@auth-tools/express";
import express, { Response } from "express";
import { Logger } from "./logger";
import { Database } from "./database";
import { compare, hash } from "./security";

//create example logger
const logger = new Logger({ capitalizeLogLevel: true });

//virtual databases
const Users = new Database<UserData>();
const RefreshTokens = new Database<{ refreshToken: string }>();

//config object for auth object
const authConfig: AuthConfig = {
  accessTokenSecret: "ACCESS_SECRET", // example values
  refreshTokenSecret: "REFRESH_SECRET", // example values
  expiresIn: 600,
  emailValidation: true,
  passwordValidation: true,
  passwordValidationRules: "Y-Y-Y-Y-10", // unused because custom use validatePassword does not use it
  sensitiveApi: false,
  sensitiveLogs: false,
  routes: {
    register: "active",
    login: "active",
    logout: "active",
    refresh: "active",
    check: "active",
  },
};

//create auth instance
const auth = new AuthInstance(authConfig, logger.log);

// //
// auth.use("", ({}) => {
//   return { serverError: false };
// });

//get a user by his email from database (required)
auth.use("getUserByMail", ({ email }) => {
  const user = Users.findOne("email", email);
  return { serverError: false, user: user || null };
});

//get a user by his username from database (required)
auth.use("getUserByName", ({ username }) => {
  const user = Users.findOne("username", username);
  return { serverError: false, user: user || null };
});

//store a user in the database (required)
auth.use("storeUser", ({ user }) => {
  Users.storeOne(user);
  return { serverError: false };
});

//check if token exists in database (required)
auth.use("checkToken", ({ refreshToken }) => {
  const storedToken = RefreshTokens.exists("refreshToken", refreshToken);
  return { serverError: false, exists: storedToken };
});

//store token in database (required)
auth.use("storeToken", ({ refreshToken }) => {
  RefreshTokens.storeOne({ refreshToken: refreshToken });
  return { serverError: false };
});

//delete token in database (required)
auth.use("deleteToken", ({ refreshToken }) => {
  RefreshTokens.deleteOne("refreshToken", refreshToken);
  return { serverError: false };
});

//custom email validation function (not required)
auth.use("validateMail", ({ email }) => {
  const valid = email.includes("@"); //email must include an @ symbol
  return { serverError: false, isValid: valid };
});

//custom password validation function (not required)
auth.use(
  "validatePassword",
  ({
    password,
    passwordRules: _passwordRules, // "_" variables used to tell ts compiler to skip unused variable
    parsedPasswordRules: _parsedPasswordRules, // "_" variables used to tell ts compiler to skip unused variable
  }) => {
    const valid = password.length >= 8; //password must be at least 8 characters
    return { serverError: false, isValid: valid };
  }
);

//custom password hashing function (not required)
auth.use("hashPassword", ({ password }) => {
  const hashedPassword = hash(password); //reverses the original password to hash it (NEVER DO THAT! JUST FOR EASY SHOWCASE)
  return { serverError: false, hashedPassword: hashedPassword };
});

//custom id generation function (not required)
auth.use("genId", ({ email: _email, username: _username }) => {
  // "_" variables used to tell ts compiler to skip unused variable
  const id = Users.items().toString(); //generate id of user by auto increment ids
  return { serverError: false, id: id };
});

//custom password checking function (not required)
auth.use("checkPassword", ({ password, hashedPassword }) => {
  const matches = compare(password, hashedPassword); //reverses the given password to compare it to hash (NEVER DO THAT! JUST FOR EASY SHOWCASE)
  return { serverError: false, matches: matches };
});

// // intercept request of
// auth.intercept("", () => {
//   return { serverError: false, intercepted: false, interceptCode: 0 };
// });

//intercept request of register
auth.intercept("register", ({ user }) => {
  logger.log("info", "New user registered:\n" + JSON.stringify(user, null, 2));
  return { serverError: false, intercepted: false, interceptCode: 0 };
});

//intercept request of login
auth.intercept("login", ({ user, accessToken, refreshToken, payload }) => {
  logger.log(
    "info",
    "User logged in:\n" +
      JSON.stringify(
        {
          user: user,
          accessToken: accessToken,
          refreshToken: refreshToken,
          payload: payload,
        },
        null,
        2
      )
  );
  return { serverError: false, intercepted: false, interceptCode: 0 };
});

//intercept request of logout
auth.intercept("logout", ({ refreshToken, payload }) => {
  logger.log(
    "info",
    "User logged out:\n" +
      JSON.stringify(
        {
          refreshToken: refreshToken,
          payload: payload,
        },
        null,
        2
      )
  );
  return { serverError: false, intercepted: false, interceptCode: 0 };
});

//intercept request of refresh
auth.intercept("refresh", ({ refreshToken, payload }) => {
  logger.log(
    "info",
    "User refreshed accessToken:\n" +
      JSON.stringify(
        {
          refreshToken: refreshToken,
          payload: payload,
        },
        null,
        2
      )
  );
  return { serverError: false, intercepted: false, interceptCode: 0 };
});

//intercept request of check
auth.intercept("check", ({ accessToken, refreshToken, payload }) => {
  logger.log(
    "info",
    "User checked tokens:\n" +
      JSON.stringify(
        {
          accessToken: accessToken,
          refreshToken: refreshToken,
          payload: payload,
        },
        null,
        2
      )
  );
  return { serverError: false, intercepted: false, interceptCode: 0 };
});

//create express app
const app = express();
app.use(express.json());

//use auth router
app.use("/auth", auth.router);

//basic api route
app.get(
  "/api/checkValidators",
  //validate that user is logged in
  auth.validateAuthMiddleware,
  async (
    _req,
    res: Response<{ payload: TokenPayload }, AuthResponseLocals>
  ) => {
    //send response data with custom sendData function
    sendData(res, 200, {
      payload: res.locals.payload,
      //check if example password is valid
      password: {
        //valid example
        valid: {
          example: "Test1234",
          ...(await auth.validatePassword("Test1234")),
        },
        //invalid example
        invalid: {
          example: "Test",
          ...(await auth.validatePassword("Test")),
        },
      },
      //check if example email is valid
      email: {
        //valid example
        valid: {
          example: "Test@1234",
          ...(await auth.validateEmail("Test@1234")),
        },
        //invalid example
        invalid: {
          example: "Test",
          ...(await auth.validatePassword("Test")),
        },
      },
    });
  }
);

//start express server
app.listen(3000);
