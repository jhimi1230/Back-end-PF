const express = require('express');
const router = express.Router();
const Estudiante = require('../models/Estudiante');
const auth = require('../middleware/auth');

// Crear un estudiante
router.post('/', auth, async (req, res) => {
    const { nombre, edad, info, email } = req.body;
    try {
        const nuevoEstudiante = new Estudiante({ nombre, edad, info, email,tipohash });
        const estudiante = await nuevoEstudiante.save();
        res.json(estudiante);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error en el servidor');
    }
});

// Obtener todos los estudiantes
router.get('/', auth, async (req, res) => {
    try {
        const estudiantes = await Estudiante.find();
        res.json(estudiantes);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error en el servidor');
    }
});

// Obtener un estudiante por ID
router.get('/:id', auth, async (req, res) => {
    try {
        const estudiante = await Estudiante.findById(req.params.id);
        if (!estudiante) {
            return res.status(404).json({ msg: 'Estudiante no encontrado' });
        }
        res.json(estudiante);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error en el servidor');
    }
});

// Actualizar un estudiante
router.put('/:id', auth, async (req, res) => {
    const { nombre, edad, grado, email } = req.body;
    const camposActualizados = { nombre, edad, grado, email };
    try {
        let estudiante = await Estudiante.findById(req.params.id);
        if (!estudiante) {
            return res.status(404).json({ msg: 'Estudiante no encontrado' });
        }
        estudiante = await Estudiante.findByIdAndUpdate(req.params.id, { $set: camposActualizados }, { new: true });
        res.json(estudiante);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error en el servidor');
    }
});

// Eliminar un estudiante
router.delete('/:id', auth, async (req, res) => {
    try {
        const estudiante = await Estudiante.findById(req.params.id);
        if (!estudiante) {
            return res.status(404).json({ msg: 'Estudiante no encontrado' });
        }
        await Estudiante.findByIdAndRemove(req.params.id);
        res.json({ msg: 'Estudiante eliminado' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error en el servidor');
    }
});

module.exports = router;
