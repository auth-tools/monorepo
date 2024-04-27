import { AuthInstance } from "../dist";
import express from "express";

const app = express();
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
});

const logger = new Logger();

auth.use("getUserByMail", async ({ email }) => ({
  err: false,
  user: { email: email, hashedPassword: "", id: "", username: "" },
}));

auth.intercept("login", async ({}) => {
  logger.log("tet", "INTERCEPT");
  return {
    err: false,
    code: 0,
  };
});

auth.log(logger.log);

app.use(auth.router);

app.listen(3000);
