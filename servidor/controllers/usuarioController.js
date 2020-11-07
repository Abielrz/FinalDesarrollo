const Usuario = require('../models/Usuario')
const bcryptjs = require('bcryptjs');
const {validationResult} = require('express-validator');
const jwt = require('jsonwebtoken');

exports.crearUsuario = async (req, res) =>{ 

        ////Verificar Errores
     const errores = validationResult(req);
     if(!errores.isEmpty()){
         return res.status(400).json({errores: errores.array()})
     }

        //Extraer Emai y Pass
        const {email, password} = req.body;
    try {
        //Verificar que el usuario sea único
        let usuario = await Usuario.findOne({email});
        if(usuario)
        {
            return res.status(400).json({msg: 'El usuario ya existe'})
        }
         //Crear Usuario
        usuario = new Usuario(req.body);
        //Hash Pass
        const salt = await bcryptjs.genSalt(10);
        usuario.password = await bcryptjs.hash(password, salt);
        //Guardar Usuario
        await usuario.save();
        //Crear y Firmar JWT
        const payload = {
            usuario:{
                id: usuario.id
            }
        };
        //Firmar Token JWT 
        jwt.sign(payload, process.env.SECRETA, {
            expiresIn: 3600 //1 Hora
        }, (error, token) => {
            if(error) throw error;
                //Mensaje de Confirmación
                res.json({token})            
        });

    } catch (error) {
        console.log(error);
        res.status(400).send('Hubo un Error');
    }        
};

