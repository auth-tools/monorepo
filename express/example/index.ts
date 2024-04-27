import { AuthInstance, UserData } from "../dist";
import express from "express";

const USERS: UserData[] = [];
const TOKENS: string[] = [];

const app = express();
app.use(express.json());
class Logger {
  constructor() {
    this.log = this.log.bind(this);
  }
  public log(level: any, data: any) {
    console.log(level, data);
  }
}

const auth = new AuthInstance({
  accessTokenSecret: "a",
  refreshTokenSecret: "a",
  sensitiveApi: false,
  sensitiveLogs: false,
  passwordValidationRules: "Y-Y-Y-Y-12",
});

const logger = new Logger();

auth.log(logger.log);

auth.use("getUserByMail", ({ email }) => {
  const user = USERS.find((usr) => usr.email === email);
  return { user: user || null };
});

auth.use("getUserByName", ({ username }) => {
  const user = USERS.find((usr) => usr.username === username);
  return { user: user || null };
});

auth.use("storeUser", ({ user }) => {
  console.log(user);
  USERS.push(user);
  return {};
});

auth.use("storeToken", ({ token }) => {
  TOKENS.push(token);
  return {};
});

auth.use("deleteToken", ({ token }) => {
  TOKENS.splice(TOKENS.indexOf(token), 1);
  console.log(TOKENS);
  return {};
});

auth.use("checkToken", ({ token }) => {
  return { exists: TOKENS.includes(token) };
});

auth.intercept("login", () => {
  console.log(TOKENS);
  return { intercepted: false, interceptCode: 0 };
});

auth.intercept("logout", () => {
  return { intercepted: true, interceptCode: 198 };
});

app.use("/auth", auth.router);

app.listen(3000);
