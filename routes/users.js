const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const { check, body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

const pool = require('../db/db');
const auth = require('../middleware/authentication');

//ruta para registrar usuario
router.post('/register',
    async (req, res) => {
        const { nombre, apellido, cedula, email, contrasena, tipo_usuario,  telefono } = req.body;
        try {
            const salt = await bcrypt.genSalt(10);
            const contrasenaEncriptada = await bcrypt.hash(contrasena, salt);//encripta password
            const id = uuidv4();
            
            //llamada bd para incertar usuario
            const response = await pool.query('INSERT INTO usuario VALUES($1, $2, $3, $4, $5, $6, $7, $8)', [ nombre, apellido, cedula, email, contrasenaEncriptada, tipo_usuario, id, telefono ]);
            res.send({results: "User created"});
        } catch (error) {
            res.send(error);
        }
})

//a esta ruta solo acceden usuarios logeados 
router.get('/usuarios', auth,
    async (req, res) => {
        try {            
            const response = await pool.query('SELECT * FROM usuario');
            res.send({usuarios: response.rows});
        } catch (error) {
            res.send(error);
        }
})


router.post('/login',
    check('email').exists(),
    check('password').exists(), 
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }

        const { email, password } = req.body;
        try {
            const user = await pool.query('SELECT id, usuario, email, contrasena, tipo_usuario FROM usuario WHERE email = $1', [email]);
            const validPassword = await bcrypt.compare(password, user.rows[0].contrasena);
    
            if(!validPassword) {
                return res.status(400).send({'error': 'Invalid credentials'});
            }
            const jwtPayload = {
                id: user.rows[0].id,
                username: user.rows[0].username,
                email: user.rows[0].email,
                tipo_usuario: user.rows[0].tipo_usuario
            }
            const token = await jwt.sign(jwtPayload, process.env.JWT_SECRET);

            res.send({token});
        } catch (error) {
            res.send(error)
        }

});

router.delete('/', auth, async (req, res) => {
    try {
        const response = await pool.query('DELETE FROM users WHERE id = $1', [req.user.id]);
        res.send({'result': 'User deleted'});
    } catch (error) {
        res.status(400).send(error)
    }
});

router.get('/verifyToken', auth, (req, res) => { 
    try {
        res.json({
            auth: true,
            username: req.user.username,
            tipo_usuario: req.user.tipo_usuario
        })
    } catch(error) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
})

module.exports = router;
