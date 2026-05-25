import express from 'express';
import cors from 'cors';
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Database from 'better-sqlite3';
import {v4 as uuidv4} from 'uuid';

const app = express();
const db = new Database('authenticator.db');

const PORT = 4000;
const JWT_SECRET= 'your_jwt'

app.use(cors());
app.use(express.json({ limit: '2mb' }));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS vaults (
    user_id TEXT PRIMARY KEY,
    vault_version INTEGER NOT NULL DEFAULT 0,
    salt TEXT,
    iv TEXT,
    ciphertext TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

function createToken(user) {
    return jwt.sign(
        {
            userId: user.id,
            email: user.email
        },
        JWT_SECRET,
        { expiresIn: '7d'
        }
    );
}

function authMiddleware(req, res, next) {
    const header = req.headers.authorization;

    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing Token' });
    }
    const token = header.slice("Bearer ".length);

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid Token' });
    }
}

app.post('/auth/register', async (req, res) => {
    try{
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
        if (existing) {
            return res.status(409).json({ error: 'Email already in use' });
        }

        const id = uuidv4();
        const passwordHash = await bcrypt.hash(password, 10);

        db.prepare(`
            INSERT INTO users (id, email, password_hash)
            VALUES (?, ?, ?)
        `).run(id, email, passwordHash);

        db.prepare(`
            INSERT INTO vaults (user_id, vault_version, salt, iv, ciphertext)
            VALUES (?, 0, NULL, NULL, NULL)
        `).run(id);
        
        const token = createToken({ id, email });

        res.json({
      token,
      user: {
        id,
        email
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Register failed" });
  }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = db.prepare(`
            SELECT * FROM users WHERE email = ?
        `).get(email);

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        const valid = await bcrypt.compare(password, user.password_hash);

        if (!valid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = createToken(user);

        res.json({
            token,
            user: {
                id: user.id,
                email: user.email
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Login failed" });
    }

});

app.get('/vault', authMiddleware, (req, res) => {
    const vault = db.prepare(`
        SELECT vault_version, salt, iv, ciphertext, updated_at FROM vaults WHERE user_id = ?
    `).get(req.user.userId);
    
    res.json({
        vaultVersion: vault?.vault_version ?? 0,
        salt: vault?.salt ?? null,
        iv: vault?.iv ?? null,
        ciphertext: vault?.ciphertext ?? null,
        updatedAt: vault?.updated_at ?? null
    });
});

app.put('/vault', authMiddleware, (req, res) => {
    const { vaultVersion, salt, iv, ciphertext } = req.body;

    if (!salt || !iv || !ciphertext) {
        return res.status(400).json({ error: 'Invaid encrypted vault' });
    }

    const current = db.prepare(`
        SELECT vault_version FROM vaults WHERE user_id = ?
    `).get(req.user.userId);

    const currentVersion = current?.vault_version ?? 0;

    if (vaultVersion < currentVersion) {
        return res.status(409).json({ error: 'Vault version conflict', currentVersion });
    }


    const nextVersion = currentVersion + 1;

    db.prepare(`
        UPDATE vaults SET vault_version = ?, salt = ?, iv = ?, ciphertext = ?, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
    `).run(nextVersion, salt, iv, ciphertext, req.user.userId);

    req.json({ ok:true, vaultVersion: nextVersion });
});

app.get('/health', (req, res) => {
    res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});



