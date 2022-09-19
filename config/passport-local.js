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

/** hay dos funciones que passport necesita para trabajar con los ids de los usuarios en toda la app:
 * serializeUser: para guardar el id del usuario en la sesion
 * deserializeUser: para obtener el usuario de la base de datos por el id */
passport.serializeUser((usuario, done) => {
  done(null, usuario.id); // _id de mongo
});

passport.deserializeUser(async (id, done) => {
  const usuario = await usuariosDao.getOne(id);
  done(null, usuario);
});