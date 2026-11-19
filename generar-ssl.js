const selfsigned = require('selfsigned');
const fs = require('fs');
const path = require('path');

async function crearCertificados() {
  const attrs = [{ name: 'commonName', value: 'localhost' }];
  // En versiones nuevas de selfsigned, generate() puede ser asíncrono
  const pems = await selfsigned.generate(attrs, { days: 365, keySize: 2048 });

  const certDir = path.join(__dirname, 'certificados');
  if (!fs.existsSync(certDir)) {
    fs.mkdirSync(certDir);
  }

  // Detectar el nombre exacto de la propiedad devuelta por la librería
  const certContent = pems.cert || pems.certificate;
  const keyContent = pems.private || pems.privateKey || pems.key;

  fs.writeFileSync(path.join(certDir, 'cert.pem'), certContent);
  fs.writeFileSync(path.join(certDir, 'key.pem'), keyContent);

  console.log('✅ ¡Certificado (cert.pem) y llave privada (key.pem) generados con éxito en /certificados!');
}

crearCertificados().catch(err => console.error('Error generando certificados:', err));