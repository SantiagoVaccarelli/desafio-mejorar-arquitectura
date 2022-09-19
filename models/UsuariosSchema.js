import mongoose from "mongoose";

export const usuariosSchema = new mongoose.Schema({
  nombre: {
    type: String,
  },
  apellido: {
    type: String,
  },
  email: {
    type: String,
    default: "",
  },
  password: {
    type: String,
    default: "",
  },
  imagen: {
    type: String,
    default: "",
  },
});