import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pg from "pg";
import dotenv from "dotenv";
import { v4 as uuidv4 } from "uuid";

dotenv.config();

const { Pool } = pg;

const app = express();

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is missing in .env");
}

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is missing in .env");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
});

app.use(cors());
app.use(express.json({ limit: "2mb" }));

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS vaults (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      vault_version INTEGER NOT NULL DEFAULT 0,
      salt TEXT,
      iv TEXT,
      ciphertext TEXT,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

function createToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
    }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing token" });
  }

  const token = header.slice("Bearer ".length);

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

app.post("/auth/register", async (req, res) => {
  const client = await pool.connect();

  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    await client.query("BEGIN");

    const existing = await client.query(
      `
      SELECT id FROM users
      WHERE email = $1
      `,
      [email]
    );

    if (existing.rows.length > 0) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        error: "User already exists",
      });
    }

    const id = uuidv4();
    const passwordHash = await bcrypt.hash(password, 12);

    await client.query(
      `
      INSERT INTO users (id, email, password_hash)
      VALUES ($1, $2, $3)
      `,
      [id, email, passwordHash]
    );

    await client.query(
      `
      INSERT INTO vaults (user_id, vault_version, salt, iv, ciphertext)
      VALUES ($1, 0, NULL, NULL, NULL)
      `,
      [id]
    );

    await client.query("COMMIT");

    const token = createToken({
      id,
      email,
    });

    res.json({
      token,
      user: {
        id,
        email,
      },
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      error: "Register failed",
    });
  } finally {
    client.release();
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE email = $1
      `,
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        error: "Invalid login",
      });
    }

    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({
        error: "Invalid login",
      });
    }

    const token = createToken(user);

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed",
    });
  }
});

app.get("/vault", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT vault_version, salt, iv, ciphertext, updated_at
      FROM vaults
      WHERE user_id = $1
      `,
      [req.user.userId]
    );

    const vault = result.rows[0];

    res.json({
      vaultVersion: vault?.vault_version ?? 0,
      salt: vault?.salt ?? null,
      iv: vault?.iv ?? null,
      ciphertext: vault?.ciphertext ?? null,
      updatedAt: vault?.updated_at ?? null,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not fetch vault",
    });
  }
});

app.put("/vault", authMiddleware, async (req, res) => {
  const client = await pool.connect();

  try {
    const { vaultVersion, salt, iv, ciphertext } = req.body;

    if (!salt || !iv || !ciphertext) {
      return res.status(400).json({
        error: "Invalid encrypted vault",
      });
    }

    await client.query("BEGIN");

    const currentResult = await client.query(
      `
      SELECT vault_version
      FROM vaults
      WHERE user_id = $1
      FOR UPDATE
      `,
      [req.user.userId]
    );

    let currentVersion = 0;

    if (currentResult.rows.length === 0) {
      await client.query(
        `
        INSERT INTO vaults (user_id, vault_version, salt, iv, ciphertext)
        VALUES ($1, 0, NULL, NULL, NULL)
        `,
        [req.user.userId]
      );
    } else {
      currentVersion = currentResult.rows[0].vault_version;
    }

    if (vaultVersion < currentVersion) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        error: "Vault version conflict",
        currentVersion,
      });
    }

    const nextVersion = currentVersion + 1;

    await client.query(
      `
      UPDATE vaults
      SET vault_version = $1,
          salt = $2,
          iv = $3,
          ciphertext = $4,
          updated_at = CURRENT_TIMESTAMP
      WHERE user_id = $5
      `,
      [nextVersion, salt, iv, ciphertext, req.user.userId]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
      vaultVersion: nextVersion,
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      error: "Could not save vault",
    });
  } finally {
    client.release();
  }
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: "connected",
    });
  } catch {
    res.status(500).json({
      ok: false,
      database: "disconnected",
    });
  }
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Backend running on http://localhost:${PORT}`);
      console.log("PostgreSQL connected");
    });
  })
  .catch((error) => {
    console.error("Database initialization failed:");
    console.error(error);
    process.exit(1);
  });