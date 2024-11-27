import jwksClient from 'jwks-rsa';
import pkg from 'jsonwebtoken';
const { verify } = pkg;

// Configurar el cliente JWKS para obtener las claves públicas
const client = jwksClient({
  jwksUri: 'https://dream-shop-sso.fly.dev/realms/quick-mart/protocol/openid-connect/certs' // URL de tu servidor de autenticación
});

// Función para obtener la clave pública correspondiente al 'kid' (Key ID) del JWT
function getKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) {
      callback(err);
      return;
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// Función para validar el JWT
function verifyJWT(token) {
  return new Promise((resolve, reject) => {
    verify(token, getKey, {
      algorithms: ['RS256'],
      audience: 'account', // Ajusta esto según tu configuración
      issuer: 'https://dream-shop-sso.fly.dev/realms/quick-mart'
    }, (err, decoded) => {
      if (err) {
        reject(new Error('Token inválido o expirado'));
      } else {
        resolve(decoded);
      }
    });
  });
}

// Función para generar la política IAM
function generatePolicy(principalId, effect, resource) {
  const authResponse = {
    principalId: principalId
  };
  if (effect && resource) {
    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: effect,
          Resource: resource
        }
      ]
    };
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
}

// Manejo de la solicitud del API Gateway
export async function handler(event) {
  const token = event.authorizationToken.split(' ')[1]; // Extraer el token del campo 'authorizationToken'
  if (!token) {
    return generatePolicy('unknown', 'Deny', event.methodArn);
  }
  try {
    // Verificar el token JWT
    const decoded = await verifyJWT(token);
    // Si el token es válido, permitimos el acceso
    return generatePolicy(decoded.sub, 'Allow', event.methodArn);
  } catch (error) {
    console.error('Error al verificar el token:', error.message);
    return generatePolicy('unknown', 'Deny', event.methodArn);
  }
}
