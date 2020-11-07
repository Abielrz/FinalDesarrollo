//Rutas para crear Usuarios

const express = require ('express');
const router = express.Router();
const usuarioController = require ('../controllers/usuarioController');
const {check} = require('express-validator');


//Crear Usuario
//      api/usuarios
router.post('/',
        [
            check('nombre','El nombre es Obligatorio').not().isEmpty(),
            check('email','Agrega un email válido').isEmail(),
            check('password','El password debe tener al menos 6 caracteres').isLength({min:6})
        ], 
    usuarioController.crearUsuario);

module.exports = router;