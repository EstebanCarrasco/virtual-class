const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const { check, body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

const pool = require('../db/db');
const auth = require('../middleware/authentication');
const { response } = require('express');

//ruta para registrar usuario
router.post('/register',
    async (req, res) => {
        const { nombre, apellido, cedula, email, contrasena, tipo_usuario,  telefono } = req.body;
        try {
            const salt = await bcrypt.genSalt(10);
            const contrasenaEncriptada = await bcrypt.hash(contrasena, salt);//encripta password
            const id = uuidv4();
            
            //llamada bd para incertar usuario
            const response = await pool.query('INSERT INTO usuario VALUES($1, $2, $3, $4, $5, $6, $7, $8)', [ nombre, apellido, cedula, email, contrasenaEncriptada, tipo_usuario, telefono, id ]);

            switch (tipo_usuario) {
                case 'Administrador':
                    await pool.query('INSERT INTO administrador VALUES($1)', [id]);
                    break;
                case 'Alumno':
                    await pool.query('INSERT INTO alumno (id, saldo_horas) VALUES($1, $2)', [id, 0]);
                    break;
                case 'Profesor':
                    await pool.query('INSERT INTO profesor (id, valor_hora, materia, experiencia) VALUES($1, $2, $3, $4)', [id, 0, '', null]);
                    break;
            }
            res.send({results: "User created"});
        } catch (error) {
            console.log(error)
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

router.get('/usuario/:id', auth,
    async (req, res) => {
        try {
            let respuesta = {};           
            const usuario = await pool.query('SELECT * FROM usuario WHERE id = $1',[req.params.id]);
            if(usuario.rows[0].tipo_usuario === 'Alumno') {
                const alumno = await pool.query('SELECT * FROM alumno WHERE id = $1',[req.params.id]);
                respuesta = {...usuario.rows[0], ...alumno.rows[0]};
            } else if(usuario.rows[0].tipo_usuario === 'Profesor') {
                const profesor = await pool.query('SELECT * FROM profesor WHERE id = $1',[req.params.id]);
                respuesta = {...usuario.rows[0], ...profesor.rows[0]};
            } else if(usuario.rows[0].tipo_usuario === 'Administrador') {
                respuesta = {...usuario.rows[0]};
            }
            res.send({usuario: respuesta});
        } catch (error) {
            res.send(error);
        }
})

router.put('/administrador/:id', auth, async (req, res) => {
    try {
        const { nombre, apellido, email, cedula, telefono } = req.body;
        await pool.query('UPDATE usuario SET nombre = $1, apellido = $2, email = $3, cedula = $4, telefono = $5 WHERE id = $6', [nombre, apellido, email, cedula, telefono, req.params.id]);
        res.send('OK')
    } catch (error) {
        res.send(error);
    }

})

router.put('/alumno/:id', auth, async (req, res) => {
    try {
        const { nombre, apellido, email, cedula, telefono, saldo_horas } = req.body;
        await pool.query('UPDATE usuario SET nombre = $1, apellido = $2, email = $3, cedula = $4, telefono = $5 WHERE id = $6', [nombre, apellido, email, cedula, telefono, req.params.id]);
        await pool.query('UPDATE alumno SET saldo_horas = $1 WHERE id = $2', [saldo_horas, req.params.id]);
        res.send('OK')
    } catch (error) {
        res.send(error);
    }

})

router.put('/profesor/:id', auth, async (req, res) => {
    try {
        const { nombre, apellido, email, cedula, telefono, valor_hora, materia, experiencia } = req.body;
        await pool.query('UPDATE usuario SET nombre = $1, apellido = $2, email = $3, cedula = $4, telefono = $5 WHERE id = $6', [nombre, apellido, email, cedula, telefono, req.params.id]);
        await pool.query('UPDATE profesor SET valor_hora = $1, materia = $2, experiencia = $3 WHERE id = $4', [valor_hora, materia, experiencia, req.params.id]);
        res.send('OK')
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
