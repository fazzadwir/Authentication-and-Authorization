import crypto from 'crypto';

export function generateRandomKey() {
    return crypto.randomBytes(32).toString('hex');
  }

export const ENCRYPTION_KEY = generateRandomKey();