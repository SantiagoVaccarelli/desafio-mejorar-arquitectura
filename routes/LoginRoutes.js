import { Router } from "express";
import passport from "passport";
import { usuariosDao as api } from "../daos/index.js";
import logger from "../utils/logger.js";
const router = Router();

router.get("/", (req, res) => {
  res.status(401).json({ message: "error en login" });
});
router.post(
  "/",
  passport.authenticate("login", {
    failureRedirect: "/api/login",
  }),
  (req, res) => {
    res.status(200).json({
      message: "Usuario logueado con éxito",
      id: req.user._id,
      email: req.user.email,
    });
  }
);

export default router;  