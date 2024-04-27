import { Router } from "express";
import { PassedProps } from "./authInstance";
import register from "./routes/register";
import login from "./routes/login";
import logout from "./routes/logout";
import refresh from "./routes/refresh";
import check from "./routes/check";

export function createAuthRouter(props: PassedProps): Router {
  const { config }: PassedProps = props;

  const authRouter = Router();

  if (config.routes.register !== "removed") {
    authRouter.post("/register", register(props));
  }
  if (config.routes.login !== "removed") {
    authRouter.post("/login", login(props));
  }
  if (config.routes.logout !== "removed") {
    authRouter.post("/logout", logout(props));
  }
  if (config.routes.refresh !== "removed") {
    authRouter.post("/refresh", refresh(props));
  }
  if (config.routes.check !== "removed") {
    authRouter.post("/check", check(props));
  }
  return authRouter;
}
