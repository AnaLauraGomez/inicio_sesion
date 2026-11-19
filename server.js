const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const dns = require('dns').promises;
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Base de datos temporal en memoria
const users = {};

// 1. VALIDACIÓN DE CORREO Y DOMINIO
async function validateEmailAndDomain(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { valid: false, message: 'Estructura de correo inválida.' };
  }

  const domain = email.split('@')[1];
  try {
    const mxRecords = await dns.resolveMx(domain);
    if (!mxRecords || mxRecords.length === 0) {
      return { valid: false, message: 'El dominio del correo no existe o no acepta correos.' };
    }
  } catch (error) {
    return { valid: false, message: 'Dominio inexistente o sin registros MX.' };
  }

  return { valid: true };
}

// 2. POLÍTICA DE CONTRASEÑAS SEGURAS
function validatePasswordPolicy(password) {
  const minLength = 8;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  return (
    password.length >= minLength &&
    hasUpper &&
    hasLower &&
    hasNumber &&
    hasSpecial
  );
}

// ENDPOINT: REGISTRO DE USUARIO
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  const emailValidation = await validateEmailAndDomain(email);
  if (!emailValidation.valid) {
    return res.status(400).json({ error: emailValidation.message });
  }

  if (!validatePasswordPolicy(password)) {
    return res.status(400).json({
      error: 'La contraseña debe tener mínimo 8 caracteres, mayúsculas, minúsculas, números y caracteres especiales.'
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const mfaSecret = speakeasy.generateSecret({ name: `AppSegura (${email})` });

  users[email] = {
    passwordHash: hashedPassword,
    mfaSecret: mfaSecret.base32,
    mfaEnabled: true
  };

  const qrImageUrl = await QRCode.toDataURL(mfaSecret.otpauth_url);

  res.json({
    message: 'Usuario registrado exitosamente.',
    qrCode: qrImageUrl,
    secret: mfaSecret.base32
  });
});

// ENDPOINT: PASO 1 LOGIN (Correo + Contraseña)
app.post('/api/login/step1', async (req, res) => {
  const { email, password } = req.body;
  const user = users[email];

  if (!user) {
    return res.status(401).json({ error: 'Credenciales incorrectas o usuario no encontrado.' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
  if (!isPasswordValid) {
    return res.status(401).json({ error: 'Credenciales incorrectas.' });
  }

  res.json({
    message: 'Paso 1 correcto. Se requiere el segundo factor (MFA).',
    requiresMFA: true,
    email: email
  });
});

// ENDPOINT: PASO 2 LOGIN (Verificación 2FA)
app.post('/api/login/step2', (req, res) => {
  const { email, mfaCode } = req.body;
  const user = users[email];

  if (!user) {
    return res.status(400).json({ error: 'Sesión no válida.' });
  }

  const verified = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token: mfaCode,
    window: 1
  });

  if (!verified) {
    return res.status(401).json({ error: 'Código MFA incorrecto o expirado.' });
  }

  res.json({ message: 'Acceso exitoso concedido al sistema.' });
});

// --- CONFIGURACIÓN SSL / HTTPS ---
const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, 'certificados', 'key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'certificados', 'cert.pem'))
};

const HTTPS_PORT = 3443;
const HTTP_PORT = 3000;

// Iniciar servidor seguro HTTPS
https.createServer(sslOptions, app).listen(HTTPS_PORT, () => {
  console.log(`Servidor SEGURO (HTTPS) ejecutándose en: https://localhost:${HTTPS_PORT}`);
});

// Servidor HTTP auxiliar que redirige automáticamente a HTTPS
http.createServer((req, res) => {
  res.writeHead(301, { "Location": `https://localhost:${HTTPS_PORT}${req.url}` });
  res.end();
}).listen(HTTP_PORT, () => {
  console.log(`↪Redirección HTTP activa en: http://localhost:${HTTP_PORT} -> HTTPS`);
});