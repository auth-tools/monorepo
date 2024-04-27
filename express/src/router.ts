import { Router } from "express";
import { PassedProps } from "./authInstance";

export function createAuthRouter(props: PassedProps): Router {
  const authRouter = Router();

  authRouter.get("/:mail", async (req, res) => {
    console.log("tge")
    const dataU = await props.useEventCallbacks.getUserByMail({
      email: req.params.mail,
    });
    const dataI = await props.interceptEventCallbacks.login({
      user: { email: "la", hashedPassword: "ka", id: "sa", username: "da" },
    });
    res.send({ use: dataU, intercept: dataI });
  });

  return authRouter;
}
