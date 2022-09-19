import { Router } from "express";
import productosRouter from "./ProductosRoutes.js";
import carritosRouter from "./CarritosRoutes.js";
import registroRouter from "./RegistroRoutes.js";
import loginRouter from "./LoginRoutes.js";
import logoutRouter from "./LogoutRoutes.js";

const apiRouter = Router();

apiRouter.use("/registro", registroRouter);
apiRouter.use("/login", loginRouter);
apiRouter.use("/productos", productosRouter);
apiRouter.use("/carritos", carritosRouter);
apiRouter.use("/logout", logoutRouter);

export default apiRouter;