import MongoClass from "../../contenedores/MongoClass.js";
import { carritosSchema } from "../../models/CarritosSchema.js";

export class MongoDBCarritos extends MongoClass {
  constructor() {
    super("carritos", carritosSchema);
  }

  async getAll() {
    const carritos = await this.collection
      .find({})
      .populate({
        path: "productos",
        populate: { path: "_id", model: "productos" },
      });
    return carritos;
  }

  async getOne(id) {
    try {
      const one = await this.collection.findById(id).populate({
        path: "productos",
        populate: { path: "_id", model: "productos" },
      });
      return one;
    } catch (err) {
      throw new Error(err);
    }
  }

  async addProductos(carrito, producto) {
    console.log(producto)
    const carritoUpdated = await this.collection.findByIdAndUpdate(
      carrito._id,
      { productos: producto}
    );
    return carritoUpdated;
  }

  async deleteProducto(carrito, productoId) {
    const productoEnCarrito = carrito.productos.find(
      (p) => p._id == productoId
    );
    if (productoEnCarrito) {
      productoEnCarrito.cantidad > 1
        ? productoEnCarrito.cantidad--
        : (carrito.productos = carrito.productos.filter(
            (p) => p._id != productoId
          ));
    } else {
      throw new Error("El producto no esta en el carrito");
    }
    const carritoUpdated = await this.collection.findByIdAndUpdate(
      carrito._id,
      { productos: carrito.productos }
    );
    return carritoUpdated;
  }
}