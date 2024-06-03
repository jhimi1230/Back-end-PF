const mongoose = require('mongoose');

const UsuarioSchema = new mongoose.Schema({
    nombre: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    rol: {
        type: String,
        default: 'estudiante'
    },
    data: {
        type: String,
        required: true
    },
    tipohash: {
        type: String,
        required: true
    },
    hash: {
        type: String,
        required: true
    }
});

module.exports = mongoose.model('usuario', UsuarioSchema);
