import crypto from 'crypto';
import { promisify } from 'util';
import { nanoid } from 'nanoid';

const generateKeyPair = promisify(crypto.generateKeyPair);
const randomBytes = promisify(crypto.randomBytes);

export function sha512(data) {
  return crypto.createHash('sha512').update(data).digest('hex');
}

export async function generateEd25519KeyPair() {
  const { publicKey, privateKey } = await generateKeyPair('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

export function derivePublicKeyFromPrivate(privateKey) {
  const keyObject = crypto.createPrivateKey(privateKey);
  const publicKey = crypto.createPublicKey(keyObject);
  return publicKey.export({ type: 'spki', format: 'pem' });
}

export function signEd25519(data, privateKey) {
  const signature = crypto.sign(null, Buffer.from(data), privateKey);
  return signature.toString('base64');
}

export function verifyEd25519(data, signature, publicKey) {
  try {
    return crypto.verify(
      null,
      Buffer.from(data),
      publicKey,
      Buffer.from(signature, 'base64')
    );
  } catch (error) {
    return false;
  }
}

export function encryptAES256GCM(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(typeof data === 'string' ? data : data.toString(), 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return {
    encrypted: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64')
  };
}

export function decryptAES256GCM(encrypted, key, iv, authTag) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encrypted, 'base64')),
    decipher.final()
  ]);
  return decrypted.toString('utf8');
}

export async function generateAES256Key() {
  return await randomBytes(32);
}

export async function deriveKey(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, 100000, 32, 'sha512', (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

export function encryptFields(data, key) {
  const encrypted = {};
  for (const [field, value] of Object.entries(data)) {
    if (value !== null && value !== undefined && value !== '') {
      encrypted[field] = encryptAES256GCM(JSON.stringify(value), key);
    }
  }
  return encrypted;
}

export function decryptFields(encryptedData, key, fields) {
  const decrypted = {};
  for (const field of fields) {
    if (encryptedData[field]) {
      const { encrypted, iv, authTag } = encryptedData[field];
      const decryptedValue = decryptAES256GCM(encrypted, key, iv, authTag);
      decrypted[field] = JSON.parse(decryptedValue);
    }
  }
  return decrypted;
}

export function generateTokenId(length = 21) {
  return nanoid(length);
}
