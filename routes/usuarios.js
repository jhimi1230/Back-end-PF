const express = require('express');
const router = express.Router();
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const Usuario = require('../models/Usuario');
const auth = require('../middleware/auth');
const crypto = require('crypto');
const { cp } = require('fs');
const { generateKeyPairSync, createSign, createVerify } = require('crypto');

// Generar par de llaves RSA
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Función para firmar datos
function signData(data, privateKey) {
    const sign = createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'hex');
}

// Función para verificar la firma
function verifySignature(data, signature, publicKey) {
    const verify = createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, 'hex');
}

// Función para generar HMAC
function generateHMAC(data, key) {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(data);
    return hmac.digest('hex');
}

// Función para verificar HMAC
function verifyHMAC(data, key, hmacToVerify) {
    const hmac = generateHMAC(data, key);
    return hmac === hmacToVerify;
}

// Función para cifrar datos utilizando AES
function encryptAES(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encryptedData = cipher.update(data, 'utf8', 'hex');
    encryptedData += cipher.final('hex');
    return iv.toString('hex') + ':' + encryptedData;
}

// Función para descifrar datos utilizando AES
function decryptAES(encryptedData, key) {
    const [ivHex, encryptedText] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decryptedData = decipher.update(encryptedText, 'hex', 'utf8');
    decryptedData += decipher.final('utf8');
    return decryptedData;
}

// Función para generar una clave a partir de una contraseña
function getKeyFromPassword(password) {
    return crypto.createHash('sha256').update(password).digest();
}

function compararTipoHash(usuario) {
    let { nombre, email, password, rol, data, tipohash, hash } = usuario;
    if (tipohash === 'Firma Digital') {
        hash = signData(data, privateKey);
        hash=hash+';;;'+publicKey;
        return { nombre, email, password, rol, data, tipohash, hash };
    } else if (tipohash === 'Almacenamiento Seguro de Contraseña') {
        hash = getKeyFromPassword(password);
        const encryptedData = encryptAES(data, hash);
        data = encryptedData;
        hash = hash.toString('hex');
        return { nombre, email, password, rol, data, tipohash, hash };
    } else if (tipohash === 'Datos en Reposo') {
        hash = getKeyFromPassword(password);
        const encryptedData = encryptAES(data, hash);
        data = encryptedData;
        hash = hash.toString('hex');
        return { nombre, email, password, rol, data, tipohash, hash };

    } else if (tipohash === 'Autenticidad de Datos') {
        const hmac = generateHMAC(data, password);
        hash = hmac;
        return { nombre, email, password, rol, data, tipohash, hash };
    } else {
        return console.log('Tipo de hash no reconocido');
    }
}

// Llamar a la función con el valor de tipohash
// Registro de usuarios
router.post('/register', async (req, res) => {
    const { nombre, email, password, rol, data, tipohash } = req.body;
    try {
        let usuario = await Usuario.findOne({ email });
        if (usuario) {
            return res.status(400).json({ msg: 'El usuario ya existe' });
        }
        let hash = "ongoing";
        usuario = new Usuario({ nombre, email, password, rol, data, tipohash, hash });
        usuario.password = await argon2.hash(password);
        const dataparaencritpar = compararTipoHash(usuario);
        usuario = new Usuario(dataparaencritpar);
        await usuario.save();
        const payload = { usuario: { id: usuario.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error en el servidor');
    }
});

// Login de usuarios
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        let usuario = await Usuario.findOne({ email });
        if (!usuario) {
            return res.status(400).json({ msg: 'Credenciales inválidas' });
        }
        const isMatch = await argon2.verify(usuario.password, password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Credenciales inválidas' });
        }
        const payload = { usuario: { id: usuario.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error en el servidor');
    }
});

// Ruta protegida para obtener información del usuario
router.get('/me', auth, async (req, res) => {
    try {
        const usuario = await Usuario.findById(req.usuario.id)
        let { nombre, email, rol, data, tipohash, password, hash } = usuario
        if (usuario.tipohash === 'Firma Digital') {
            const verificar = hash.split(';;;');
            const isValidSignature = verifySignature(data, verificar[0], verificar[1]); 
            const dataamostrar = { nombre, email, rol, data, tipohash, isValidSignature};
            res.json(dataamostrar);           
        } else if (usuario.tipohash === 'Almacenamiento Seguro de Contraseña') {
            const retrievedHashBuffer = Buffer.from(usuario.hash, 'hex');
            usuario.data = decryptAES(usuario.data, retrievedHashBuffer);
            data = usuario.data;
            const dataamostrar = { nombre, email, rol, data, tipohash };
            res.json(dataamostrar);
        } else if (usuario.tipohash === 'Datos en Reposo') {
            const retrievedHashBuffer = Buffer.from(usuario.hash, 'hex');
            usuario.data = decryptAES(usuario.data, retrievedHashBuffer);
            data = usuario.data;
            const dataamostrar = { nombre, email, rol, data, tipohash };
            res.json(dataamostrar);
        } else if (usuario.tipohash === 'Autenticidad de Datos') {
            const isValidHMAC = verifyHMAC(data, password, hash);
            if (isValidHMAC) {
                tipohash += ' ( la firma es válida)';
            } else {
                tipohash += ' ( la firma no es válida)';
            }
            const dataamostrar = { nombre, email, rol, data, tipohash };
            res.json(dataamostrar);
        }
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error en el servidor');
    }
});

module.exports = router;
