import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { usuariosDao } from "../daos/index.js";
import { encryptPassword, comparePassword } from "../config/bcrypt.js";

passport.use(
  "registro",
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
      passReqToCallback: true,
    },
    async (req, email, password, done) => {
      const usuario = await usuariosDao.findByEmail(email);
      if (usuario) {
        return done(null, false, { message: "El usuario ya existe" });
      }
      req.body.password = await encryptPassword(password);
      const nuevoUsuario = await usuariosDao.create(req.body);
      return done(null, nuevoUsuario);
    }
  )
);

passport.use(
  "login",
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
      passReqToCallback: true,
    },
    async (req, email, password, done) => {
      console.log(email, password);
      const usuario = await usuariosDao.findByEmail(email);
      console.log(usuario);
      if (!usuario) {
        return done(null, false, { message: "El usuario no existe" });
      }
      const isTruePassword = await comparePassword(password, usuario.password);
      if (!isTruePassword) {
        return done(null, false, { message: "El password es incorrecto" });
      }
      return done(null, usuario);
    }
  )
);

passport.serializeUser((usuario, done) => {
  done(null, usuario.id);
});

passport.deserializeUser(async (id, done) => {
  const usuario = await usuariosDao.getOne(id);
  done(null, usuario);
});