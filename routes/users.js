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
            //y ademas realiza entrada a la tabla del tipo de usuario que sea
            const response = await pool.query('INSERT INTO usuario VALUES($1, $2, $3, $4, $5, $6, $7, $8)', [ nombre, apellido, cedula, email, contrasenaEncriptada, tipo_usuario, id ,telefono  ]);

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

//obtiene la info de un solo usuario dependiendo del tipo de usuario
//paso id de la (url) del usuario que quiero obtener 
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

router.get('/current-usuario/', auth,
    async (req, res) => { 
        try {
            let respuesta = {};           
            const usuario = await pool.query('SELECT * FROM usuario WHERE id = $1',[req.user.id]);
            if(usuario.rows[0].tipo_usuario === 'Alumno') {
                const alumno = await pool.query('SELECT * FROM alumno WHERE id = $1',[req.user.id]);
                respuesta = {...usuario.rows[0], ...alumno.rows[0]};
            } else if(usuario.rows[0].tipo_usuario === 'Profesor') {
                const profesor = await pool.query('SELECT * FROM profesor WHERE id = $1',[req.user.id]);
                respuesta = {...usuario.rows[0], ...profesor.rows[0]};
            } else if(usuario.rows[0].tipo_usuario === 'Administrador') {
                respuesta = {...usuario.rows[0]};
            }
            res.send({usuario: respuesta});
        } catch (error) {
            res.send(error);
        }
})


router.get('/profesores', auth, async (req, res) => {
    try {
        const profesores = await pool.query('SELECT * FROM profesor INNER JOIN usuario ON profesor.Id = usuario.Id');
        res.send(profesores.rows)
    } catch (error) {
        res.send(error);
    }
})

router.get('/profesor/:id', auth, async (req, res) => {
    try {
        const profesores = await pool.query('SELECT * FROM profesor INNER JOIN usuario ON profesor.Id = usuario.Id WHERE profesor.Id = $1', [req.params.id]);
        res.send(profesores.rows)
    } catch (error) {
        res.send(error);
    }
})

//ruta para actualizar la tabla administrador, le paso todos los valores del formulario
//query actualiza la tabla administrador 
router.put('/administrador/:id', auth, async (req, res) => {
    try {
        const { nombre, apellido, email, cedula, telefono } = req.body;
        await pool.query('UPDATE usuario SET nombre = $1, apellido = $2, email = $3, cedula = $4, telefono = $5 WHERE id = $6', [nombre, apellido, email, cedula, telefono, req.params.id]);
        res.send('OK')
    } catch (error) {
        res.send(error);
    }

})

//ruta para actualizar la tabla alumno, le paso todos los valores del formulario
//query actualiza la tabla alumno 
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

//ruta para actualizar la tabla profesor, le paso todos los valores del formulario
//query actualiza la tabla profesor
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

router.get('/alumno', auth,
    async (req, res) => {
        try {            
            const response = await pool.query('SELECT * FROM usuario INNER JOIN Alumno ON Usuario.Id = Alumno.Id');
            res.send({usuarios: response.rows});
        } catch (error) {
            res.send(error);
        }
})



router.delete('/:id', auth, async (req, res) => {
    try {
        console.log(req.params.id)
        const response = await pool.query('DELETE FROM usuario WHERE id = $1', [req.params.id]);
        console.log(response)
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


router.post('/consulta', auth, async (req, res) => {
    try {
        const { profesor, planteo } = req.body;
        const consultaId = uuidv4();
        await pool.query('INSERT INTO consultas (id, alumno, profesor, planteo, respondido, fecha) VALUES($1, $2, $3, $4, $5, $6)', [consultaId, req.user.id, profesor, planteo, false, new Date()]);
        await pool.query('UPDATE alumno SET saldo_horas = saldo_horas - 1 WHERE id = $1', [req.user.id]);

    } catch (error) {
        console.log(error)
        res.send(error);
    }
})

router.get('/consulta', auth, async (req, res) => {
    try {
        const consultas = await pool.query('SELECT consultas.id AS consultaId, * FROM consultas INNER JOIN alumno ON alumno.id = consultas.alumno INNER JOIN usuario ON alumno.id = usuario.id WHERE profesor = $1', [req.user.id]);
        res.send(consultas.rows);
    } catch (error) {
        console.log(error)
        res.send(error);
    }
})

router.get('/consulta-alumno', auth, async (req, res) => {
    try {
        const consultas = await pool.query('SELECT consultas.id AS consultaId, * FROM consultas INNER JOIN profesor ON profesor.id = consultas.profesor INNER JOIN usuario ON profesor.id = usuario.id WHERE alumno = $1', [req.user.id]);
        res.send(consultas.rows);
    } catch (error) {
        console.log(error)
        res.send(error);
    }
})


router.get('/consulta/:id', auth, async (req, res) => {
    try {
        const consultas = await pool.query('SELECT planteo, respuesta FROM consultas WHERE id = $1', [req.params.id]);
        res.send(consultas.rows);
    } catch (error) {
        console.log(error)
        res.send(error);
    }
})


router.put('/consulta', auth, async (req, res) => {
    try {
        const { respuesta, id } = req.body;
        await pool.query('UPDATE consultas SET respuesta = $1, respondido = true WHERE consultas.id = $2', [respuesta, id])
    } catch (error) {
        res.send(error)
    }
})

router.post('/horasDocente', auth, async (req, res) => {
    try {
        const id = uuidv4();
        const { cantidad, monto, comprobante } = req.body;
        await pool.query('INSERT INTO horasdocente (id, cantidad, monto, alumno, fecha, comprobante) VALUES($1,$2,$3,$4,$5,$6)', [id, cantidad, monto, req.user.id, new Date(), comprobante]);
    } catch (error) {
        console.log(error)
        res.send(error)
    }
})

router.get('/horasDocente', auth, async (req,res) => {
    try {
        const horasDocente = await pool.query('SELECT horasdocente.Id AS horasId, * FROM horasdocente INNER JOIN usuario ON horasdocente.alumno = usuario.id');
        res.send(horasDocente.rows); 
    } catch (error) {
        console.log(error)
        res.send(error)
    }
})

router.post('/acreditarHoras', auth, async (req, res) => {
    try {
        const { alumno, cantidad, horasId} = req.body;
        console.log(horasId)
        await pool.query('UPDATE alumno SET saldo_horas = saldo_horas + $1 WHERE id = $2', [cantidad, alumno]);
        await pool.query('DELETE FROM horasdocente WHERE id = $1', [horasId])
        res.send('ok')
    } catch (error) {
        console.log(error)
        res.send(error)
    }
})


module.exports = router;
