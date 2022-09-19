import { Router } from 'express';
import { productosDao as api } from '../daos/index.js';
const productosRouter = Router();


productosRouter.get('/', async (req, res) => {
    try{
        const productos = await api.getAll();
        productos? res.status(200).json(productos) : res.status(404).json({message: 'No hay productos disponibles'});
    }catch (err){
        res.status(500).json({message: err.message});
    }
});

productosRouter.get('/:id', async (req, res) => {
    try{
        const producto = await api.getOne(req.params.id);
        producto? res.status(200).json(producto) : res.status(404).json({message: 'Producto no encontrado. id: ' + req.params.id});
    }
    catch (err){
        res.status(500).json({message: err.message});
    }
});

productosRouter.post('/', async (req, res) => {
    try{
        const nuevoProducto = await api.create(req.body);
        res.status(201).json({
            message: 'Producto creado con éxito',
            producto: nuevoProducto});
    }catch (err){
        res.status(500).json({message: err.message});
    }
});

productosRouter.put('/:id', async (req, res) => {
    try{
        const productoActualizado = await api.update(req.params.id, req.body);
        res.json({
            message: 'Producto actualizado correctamente',
            id: productoActualizado._id
            });
    }catch (err){
        res.status(500).json({message: err.message});
    }
});

productosRouter.delete('/:id', async (req, res) => {
    try{
        const productoBorrado = await api.delete(req.params.id);
        res.json({
            message: 'Producto borrado correctamente',
            id: productoBorrado._id
            });
    }
    catch (err){
        res.status(500).json({message: err.message});
    }
});

export default productosRouter;