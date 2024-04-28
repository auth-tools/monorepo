import { RequestHandler, Router } from "express";
import { PassedProps } from "./authInstance";
import register from "./routes/register";
import login from "./routes/login";
import logout from "./routes/logout";
import refresh from "./routes/refresh";
import check from "./routes/check";

//wrapper for express RequestHandler that defines req.body params
export type AuthRequestHandler<ReqBody> = RequestHandler<
  {},
  {},
  Partial<ReqBody>
>;

//factory for the auth router that provides all props of the AuthInstance class
export function createAuthRouter(props: PassedProps): Router {
  const { config }: PassedProps = props;

  //create express router
  const authRouter = Router();

  //load /register route when it is not disabled
  if (config.routes.register !== "removed") {
    authRouter.post("/register", register(props));
  }
  //load /login route when it is not disabled
  if (config.routes.login !== "removed") {
    authRouter.post("/login", login(props));
  }
  //load /logout route when it is not disabled
  if (config.routes.logout !== "removed") {
    authRouter.post("/logout", logout(props));
  }
  //load /refresh route when it is not disabled
  if (config.routes.refresh !== "removed") {
    authRouter.post("/refresh", refresh(props));
  }
  //load /check route when it is not disabled
  if (config.routes.check !== "removed") {
    authRouter.post("/check", check(props));
  }

  //return the authRouter from factory
  return authRouter;
}
