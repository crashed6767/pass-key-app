import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

export class JsonStateStore {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.statePath = path.join(dataDir, 'state.json');
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.state = this.#load();
  }

  #load() {
    if (!fs.existsSync(this.statePath)) {
      return { users: [], bootstrapUsed: false, createdAt: new Date().toISOString() };
    }
    const parsed = JSON.parse(fs.readFileSync(this.statePath, 'utf8'));
    parsed.users ||= [];
    parsed.bootstrapUsed = Boolean(parsed.bootstrapUsed);
    for (const user of parsed.users) user.credentials ||= [];
    return parsed;
  }

  save() {
    const tmp = `${this.statePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.state, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.statePath);
  }

  get users() {
    return this.state.users;
  }

  get bootstrapUsed() {
    return Boolean(this.state.bootstrapUsed);
  }

  set bootstrapUsed(value) {
    this.state.bootstrapUsed = Boolean(value);
  }

  createBootstrapUser(username, displayName) {
    return {
      id: randomBase64Url(32),
      username,
      displayName: displayName || username,
      credentials: [],
      createdAt: new Date().toISOString(),
    };
  }

  addUser(user) {
    this.state.users.push(user);
    this.save();
  }

  findUserById(id) {
    return this.state.users.find((user) => user.id === id) || null;
  }

  findCredential(credentialID) {
    for (const user of this.state.users) {
      const credential = user.credentials.find((candidate) => candidate.id === credentialID);
      if (credential) return { user, credential };
    }
    return null;
  }

  addCredential(user, credential) {
    if (!user.credentials.some((existing) => existing.id === credential.id)) {
      user.credentials.push(credential);
    }
    user.updatedAt = new Date().toISOString();
    this.save();
  }
}

export function randomBase64Url(bytes) {
  return crypto.randomBytes(bytes).toString('base64url');
}
