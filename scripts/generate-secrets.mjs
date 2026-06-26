import crypto from 'crypto';

console.log(`SESSION_SECRET=${crypto.randomBytes(48).toString('base64url')}`);
console.log(`BOOTSTRAP_TOKEN=${crypto.randomBytes(32).toString('base64url')}`);
