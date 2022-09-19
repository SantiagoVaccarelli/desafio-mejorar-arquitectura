import MongoClass from "../../contenedores/MongoClass.js";
import { usuariosSchema } from "../../models/UsuariosSchema.js";

export class MongoDBUsuarios extends MongoClass {
  constructor() {
    super("usuarios", usuariosSchema);
  }

  async findByEmail(email) {
    try {
      const usuario = await this.collection.findOne({ email: email });
      return usuario;
    } catch (err) {
      throw new Error(err);
    }
  }
}