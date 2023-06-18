// Variables de entorno 
import * as dotenv from "dotenv";
dotenv.config();
const ONE_MINUTE_M = 60 * 1000;
const SECREt = process.env.JWT_SECRET;
const PRIVATE_KEY_PATH = process.env.PRIVATE_KEY_PATH;
const PUBLIC_KEY_PATH = process.env.PUBLIC_KEY_PATH;
import jwt from "jsonwebtoken";
import fs from "node:fs";

export const signToken = (user) => {
    // se contruye el payload

  const payload = {
    sub: user.id,
    name: user.fullname,
    exp: Date.now() + ONE_MINUTE_M
  };

  // solo si se tiene la llave privada se firma con RS256
  if (PRIVATE_KEY_PATH) {
    const privateKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
    return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
  }

  // Se retorna el token firmado
  return jwt.sign(payload, SECREt);
};

export const verifyToken = (token) => {
  if ( PUBLIC_KEY_PATH ) {
    const publicKey = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
    return jwt.verify(token, publicKey);
  }
  return jwt.verify(token, SECREt);
};

export const validateExpiration = (payload) => {
  if (Date.now() > payload.exp) {
    throw new Error("Token caducado");
  }
};