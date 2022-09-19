import { Router } from "express";
import passport from "passport";
import { usuariosDao as api } from "../daos/index.js";
import "../config/passport-local.js";
const router = Router();

router.get("/", (req, res) => {
  res.status(500).json({ message: "error en registro" });
});

router.post(
  "/",
  passport.authenticate("registro", {
    failureRedirect: "/api/registro",
  }),
  (req, res) => {
    res.status(201).json({
      message: "Usuario registrado con éxito",
      id: req.user._id,
      email: req.user.email,
    });
  }
);

export default router;