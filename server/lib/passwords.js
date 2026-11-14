// The browser never sends the password. It sends authKey = HKDF(PBKDF2(password)),
// which the server treats as a high-entropy password and hashes again with scrypt
// (memory-hard) so a database leak does not let an attacker log in.
import { scrypt, randomBytes, randomInt, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
const PARAMS = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export async function hashAuthKey(authKeyB64) {
  const salt = randomBytes(16);
  const hash = await scryptAsync(Buffer.from(authKeyB64, 'base64'), salt, 32, PARAMS);
  return { auth_hash: hash.toString('hex'), auth_salt: salt.toString('hex') };
}

export async function verifyAuthKey(authKeyB64, user) {
  // Always run scrypt, even for unknown users, so timing does not reveal account existence.
  const salt = user?.auth_salt ? Buffer.from(user.auth_salt, 'hex') : Buffer.alloc(16);
  const expected = user?.auth_hash ? Buffer.from(user.auth_hash, 'hex') : Buffer.alloc(32, 1);
  const got = await scryptAsync(Buffer.from(String(authKeyB64), 'base64'), salt, 32, PARAMS);
  return timingSafeEqual(got, expected) && !!user?.auth_hash;
}

export function newEnrollmentCode() {
  // 4 groups of 4 from an unambiguous alphabet (~80 bits)
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 16; i++) s += alphabet[randomInt(alphabet.length)];
  return s.match(/.{4}/g).join('-');
}

export const hashCode = (code) => createHash('sha256').update(String(code).toUpperCase().replace(/[^A-Z0-9]/g, '')).digest('hex');
export const sha256 = (v) => createHash('sha256').update(v).digest('hex');
