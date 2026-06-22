require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "ak-koudougou-secret-2026";

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL manquant. Ajoute PostgreSQL sur Railway.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("railway") ? { rejectUnauthorized: false } : false,
});

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    return await client.query(sql, params);
  } finally {
    client.release();
  }
}

function normalizeRole(role) {
  return String(role || "").toLowerCase().trim();
}

function requireRole(user, roles) {
  if (!user) return false;
  const role = normalizeRole(user.role);
  if (role.includes("admin") || role.includes("super")) return true;
  return roles.includes(role);
}

async function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.replace("Bearer ", "").trim();

    if (!token) return res.status(401).json({ error: "Session absente" });

    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await query(
      "SELECT id, full_name, username, role, active FROM users WHERE id=$1 AND active=true LIMIT 1",
      [decoded.id]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "Session invalide" });
    }

    req.user = result.rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: "Session expirée ou invalide" });
  }
}

async function getUserFromHeader(req) {
  // Compatibilité ancienne interface : x-user-id
  const id = req.headers["x-user-id"];
  if (!id) return null;
  const r = await query("SELECT id, full_name, username, role, active FROM users WHERE id=$1", [id]);
  return r.rows[0] || null;
}

async function getCurrentUser(req) {
  if (req.user) return req.user;

  const header = req.headers.authorization || "";
  const token = header.replace("Bearer ", "").trim();

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);

      const result = await query(
        "SELECT id, full_name, username, role, active FROM users WHERE id=$1 AND active=true LIMIT 1",
        [decoded.id]
      );

      if (result.rows.length) {
        return result.rows[0];
      }
    } catch (err) {
      return null;
    }
  }

  return await getUserFromHeader(req);
}

async function addLog(user, action, details = "") {
  try {
    await query(
      "INSERT INTO logs(user_name, role, action, details) VALUES($1,$2,$3,$4)",
      [user?.full_name || user?.fullName || "Système", user?.role || "system", action, details]
    );
  } catch (e) {
    console.error("Erreur log:", e.message);
  }
}

async function initDb() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      plain_password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','cashier','waitress','storekeeper')),
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      category TEXT NOT NULL,
      price INTEGER NOT NULL DEFAULT 0,
      qty INTEGER NOT NULL DEFAULT 0,
      alert_qty INTEGER NOT NULL DEFAULT 0,
      delivery_photo TEXT,
      created_by TEXT,
      updated_by TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS stock_history (
      id SERIAL PRIMARY KEY,
      product_name TEXT NOT NULL,
      before_qty INTEGER NOT NULL,
      after_qty INTEGER NOT NULL,
      diff_qty INTEGER NOT NULL,
      action_type TEXT NOT NULL,
      user_name TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS tables_bar (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS invoices (
      id SERIAL PRIMARY KEY,
      number TEXT UNIQUE NOT NULL,
      table_name TEXT,
      waitress_id INTEGER,
      waitress_name TEXT,
      cashier_id INTEGER,
      cashier_name TEXT,
      total INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'unpaid',
      payment_mode TEXT,
      amount_given INTEGER DEFAULT 0,
      change_amount INTEGER DEFAULT 0,
      cancel_reason TEXT,
      paid_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS invoice_items (
      id SERIAL PRIMARY KEY,
      invoice_id INTEGER REFERENCES invoices(id) ON DELETE CASCADE,
      product_id INTEGER,
      product_name TEXT NOT NULL,
      qty INTEGER NOT NULL,
      price INTEGER NOT NULL,
      total INTEGER NOT NULL
    );
  `);

  await query(`
  CREATE TABLE IF NOT EXISTS payment_gaps (
    id SERIAL PRIMARY KEY,
    invoice_id INTEGER REFERENCES invoices(id) ON DELETE CASCADE,
    invoice_number TEXT,
    amount INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    reported_by TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  );
`);
await query(`
  CREATE TABLE IF NOT EXISTS cash_withdrawals (
    id SERIAL PRIMARY KEY,
    amount INTEGER NOT NULL,
    reason TEXT,
    created_by TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  );
`);
  await query(`
    CREATE TABLE IF NOT EXISTS cash_closings (
      id SERIAL PRIMARY KEY,
      closing_date DATE NOT NULL,
      cashier_id INTEGER,
      cashier_name TEXT,
      cash_total INTEGER DEFAULT 0,
      electronic_total INTEGER DEFAULT 0,
      total INTEGER DEFAULT 0,
      ticket_count INTEGER DEFAULT 0,
      forced BOOLEAN DEFAULT FALSE,
      unpaid_count INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS logs (
      id SERIAL PRIMARY KEY,
      user_name TEXT NOT NULL,
      role TEXT,
      action TEXT NOT NULL,
      details TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  const admin = await query("SELECT id FROM users WHERE username=$1", ["admin"]);
  if (admin.rowCount === 0) {
    const hash = await bcrypt.hash("admin123", 10);
    await query(
      "INSERT INTO users(full_name, username, password_hash, plain_password, role, active) VALUES($1,$2,$3,$4,$5,true)",
      ["Super Administrateur", "admin", hash, "admin123", "admin"]
    );
  }

  const t = await query("SELECT id FROM tables_bar LIMIT 1");
  if (t.rowCount === 0) {
    for (const name of ["Table 1", "Table 2", "Table 3", "VIP 1"]) {
      await query("INSERT INTO tables_bar(name) VALUES($1) ON CONFLICT DO NOTHING", [name]);
    }
  }
}

app.put("/api/users/:id", authMiddleware, async (req, res) => {
  try {
    if (!requireRole(req.user, ["admin"])) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    const { fullName, username, password, role, active } = req.body;

    const existing = await query(
      "SELECT id FROM users WHERE username=$1 AND id<>$2 LIMIT 1",
      [username, req.params.id]
    );

    if (existing.rows.length) {
      return res.status(400).json({ error: "Nom utilisateur déjà utilisé" });
    }

    let sql;
    let params;

    if (password && password.trim()) {
      const passwordHash = await bcrypt.hash(password, 10);
      sql = `
        UPDATE users 
        SET full_name=$1, username=$2, password_hash=$3, plain_password=$4, role=$5, active=$6
        WHERE id=$7
        RETURNING id, full_name, username, plain_password, role, active
      `;
      params = [fullName, username, passwordHash, password, role, active, req.params.id];
    } else {
      sql = `
        UPDATE users 
        SET full_name=$1, username=$2, role=$3, active=$4
        WHERE id=$5
        RETURNING id, full_name, username, plain_password, role, active
      `;
      params = [fullName, username, role, active, req.params.id];
    }

    const result = await query(sql, params);

    res.json(result.rows[0]);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.patch("/api/users/:id/password", authMiddleware, async (req, res) => {

  try{

    if(!requireRole(req.user, ["admin"])){
      return res.status(403).json({
        error:"Accès refusé"
      });
    }

    const password = String(req.body.password || "").trim();

    if(password.length < 3){
      return res.status(400).json({
        error:"Mot de passe trop court"
      });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await query(
      `UPDATE users
       SET password_hash=$1,
           plain_password=$2
       WHERE id=$3
       RETURNING id, full_name, username`,
      [
        hash,
        password,
        req.params.id
      ]
    );

    if(!result.rows.length){
      return res.status(404).json({
        error:"Utilisateur introuvable"
      });
    }

    await addLog(
      req.user,
      "Réinitialisation mot de passe",
      result.rows[0].full_name
    );

    res.json({
      success:true
    });

  }catch(err){

    console.error(err);

    res.status(500).json({
      error:"Erreur serveur"
    });

  }

});

app.patch("/api/users/:id/toggle", authMiddleware, async (req, res) => {
  try {
    if (!requireRole(req.user, ["admin"])) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    const result = await query(
      `UPDATE users 
       SET active = NOT active 
       WHERE id=$1 
       RETURNING id, full_name, username, plain_password, role, active`,
      [req.params.id]
    );

    res.json(result.rows[0]);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.delete("/api/users/:id", authMiddleware, async (req, res) => {
  try {
    if (!requireRole(req.user, ["admin"])) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    if (String(req.user.id) === String(req.params.id)) {
      return res.status(400).json({ error: "Impossible de supprimer votre propre compte" });
    }

    const result = await query(
      "DELETE FROM users WHERE id=$1 RETURNING id, full_name, username",
      [req.params.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Utilisateur introuvable" });
    }

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/my-orders", authMiddleware, async (req, res) => {
  try {
    const result = await query(
      `SELECT *
       FROM invoices
       WHERE waitress_id=$1
       ORDER BY id DESC
       LIMIT 200`,
      [req.user.id]
    );

    res.json(result.rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.put("/api/products/:id", authMiddleware, async (req, res) => {
  try {
    if (!requireRole(req.user, ["admin", "storekeeper"])) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    const { name, category, price, qty, alertQty, deliveryPhoto } = req.body;

    const old = await query("SELECT * FROM products WHERE id=$1", [req.params.id]);

    if (!old.rows.length) {
      return res.status(404).json({ error: "Produit introuvable" });
    }

    const before = Number(old.rows[0].qty);
    const after = Number(qty);

    const result = await query(
      `UPDATE products
       SET name=$1, category=$2, price=$3, qty=$4, alert_qty=$5,
           delivery_photo=COALESCE($6, delivery_photo),
           updated_by=$7, updated_at=NOW()
       WHERE id=$8
       RETURNING *`,
      [name, category, price, qty, alertQty, deliveryPhoto || null, req.user.full_name, req.params.id]
    );

    await query(
      "INSERT INTO stock_history(product_name,before_qty,after_qty,diff_qty,action_type,user_name) VALUES($1,$2,$3,$4,$5,$6)",
      [name, before, after, after - before, "Modification", req.user.full_name]
    );

    res.json(result.rows[0]);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.delete("/api/products/:id", authMiddleware, async (req, res) => {
  try {
    if (!requireRole(req.user, ["admin"])) {
      return res.status(403).json({ error: "Seul Admin peut supprimer un produit" });
    }

    const result = await query(
      "DELETE FROM products WHERE id=$1 RETURNING *",
      [req.params.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Produit introuvable" });
    }

    await addLog(req.user, "Suppression produit", result.rows[0].name);

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.patch("/api/products/:id/restock", authMiddleware, async (req, res) => {
  try {

    if (!requireRole(req.user, ["admin", "storekeeper"])) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    const qtyToAdd = Number(req.body.qty);

    if (!qtyToAdd || qtyToAdd <= 0) {
      return res.status(400).json({ error: "Quantité invalide" });
    }

    const old = await query(
      "SELECT * FROM products WHERE id=$1",
      [req.params.id]
    );

    if (!old.rows.length) {
      return res.status(404).json({ error: "Produit introuvable" });
    }

    const p = old.rows[0];

    const before = Number(p.qty);
    const after = before + qtyToAdd;

    const result = await query(
      `UPDATE products
       SET qty=$1,
           updated_by=$2,
           updated_at=NOW()
       WHERE id=$3
       RETURNING *`,
      [
        after,
        req.user.full_name,
        req.params.id
      ]
    );

    await query(
      `INSERT INTO stock_history
      (
        product_name,
        before_qty,
        after_qty,
        diff_qty,
        action_type,
        user_name
      )
      VALUES($1,$2,$3,$4,$5,$6)`,
      [
        p.name,
        before,
        after,
        qtyToAdd,
        "Réapprovisionnement",
        req.user.full_name
      ]
    );

    res.json(result.rows[0]);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "Erreur réapprovisionnement"
    });

  }
});

app.get("/api/backup", authMiddleware, async (req, res) => {
  try {
    if (!requireRole(req.user, ["admin"])) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    const users = await query("SELECT id, full_name, username, plain_password, role, active, created_at FROM users ORDER BY id ASC");
    const products = await query("SELECT * FROM products ORDER BY id ASC");
    const stockHistory = await query("SELECT * FROM stock_history ORDER BY id ASC");
    const tables = await query("SELECT * FROM tables_bar ORDER BY id ASC");
    const invoices = await query("SELECT * FROM invoices ORDER BY id ASC");
    const invoiceItems = await query("SELECT * FROM invoice_items ORDER BY id ASC");
    const closings = await query("SELECT * FROM cash_closings ORDER BY id ASC");
    const logs = await query("SELECT * FROM logs ORDER BY id ASC");

    res.json({
      exportedAt: new Date().toISOString(),
      users: users.rows,
      products: products.rows,
      stockHistory: stockHistory.rows,
      tables: tables.rows,
      invoices: invoices.rows,
      invoiceItems: invoiceItems.rows,
      closings: closings.rows,
      logs: logs.rows
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur export sauvegarde" });
  }
});



app.get("/api/health", (req, res) => res.json({ ok: true, app: "LOUNCH KOUDOUGOU AK" }));

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await query(
      "SELECT * FROM users WHERE username=$1 AND active=true LIMIT 1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Utilisateur introuvable" });
    }

    const user = result.rows[0];

    let passwordOk = false;
    if (user.plain_password === password) {
      passwordOk = true;
    } else if (user.password_hash) {
      passwordOk = await bcrypt.compare(password, user.password_hash);
    }

    if (!passwordOk) {
      return res.status(401).json({ error: "Mot de passe incorrect" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "12h" }
    );

    await addLog(user, "Connexion", "Connexion au logiciel");

    return res.json({
      success: true,
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        username: user.username,
        role: user.role,
        active: user.active
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/users", authMiddleware, async (req, res) => {
  try {
    if (!requireRole(req.user, ["admin"])) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    const result = await query(
      `SELECT id, full_name, username, plain_password, role, active, created_at
       FROM users
       ORDER BY id DESC`
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/users", authMiddleware, async (req, res) => {
  try {
    if (!requireRole(req.user, ["admin"])) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    const { fullName, username, password, role } = req.body;

    if (!fullName || !username || !password || !role) {
      return res.status(400).json({ error: "Champs obligatoires manquants" });
    }

    const existing = await query("SELECT id FROM users WHERE username=$1 LIMIT 1", [username]);
    if (existing.rows.length) {
      return res.status(400).json({ error: "Nom utilisateur déjà utilisé" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const r = await query(
      `INSERT INTO users(full_name, username, password_hash, plain_password, role, active)
       VALUES($1, $2, $3, $4, $5, true) RETURNING id, full_name, username, plain_password, role, active, created_at`,
      [fullName, username, passwordHash, password, role]
    );

    await addLog(req.user, "Création utilisateur", `${fullName} (${role})`);
    res.json({ success: true, user: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/products", async (req, res) => {
  const r = await query("SELECT * FROM products ORDER BY name ASC");
  res.json(r.rows);
});

app.post("/api/products", authMiddleware, async (req, res) => {
  const user = req.user;

  if (!requireRole(user, ["admin", "storekeeper"])) {
    return res.status(403).json({ error: "Accès refusé" });
  }

  const { name, category, price, qty, alertQty, deliveryPhoto } = req.body;

  const existing = await query("SELECT * FROM products WHERE LOWER(name)=LOWER($1)", [name]);

  if (existing.rowCount > 0) {
    const p = existing.rows[0];

    if (user.role !== "admin" && (Number(price) !== Number(p.price) || Number(alertQty) !== Number(p.alert_qty))) {
      return res.status(403).json({ error: "Seul Admin peut modifier prix ou seuil" });
    }

    const before = Number(p.qty);
    const after = before + Number(qty);

    const r = await query(
      `UPDATE products 
       SET category=$1, price=$2, qty=$3, alert_qty=$4, delivery_photo=COALESCE($5, delivery_photo), updated_by=$6, updated_at=NOW()
       WHERE id=$7 RETURNING *`,
      [
        category,
        user.role === "admin" ? price : p.price,
        after,
        user.role === "admin" ? alertQty : p.alert_qty,
        deliveryPhoto || null,
        user.full_name,
        p.id
      ]
    );

    await query(
      "INSERT INTO stock_history(product_name,before_qty,after_qty,diff_qty,action_type,user_name) VALUES($1,$2,$3,$4,$5,$6)",
      [p.name, before, after, Number(qty), "Réapprovisionnement", user.full_name]
    );

    return res.json(r.rows[0]);
  }

  const r = await query(
    "INSERT INTO products(name,category,price,qty,alert_qty,delivery_photo,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *",
    [name, category, price, qty, alertQty, deliveryPhoto || null, user.full_name]
  );

  await query(
    "INSERT INTO stock_history(product_name,before_qty,after_qty,diff_qty,action_type,user_name) VALUES($1,$2,$3,$4,$5,$6)",
    [name, 0, qty, qty, "Création", user.full_name]
  );

  res.json(r.rows[0]);
});

app.get("/api/stock-history", async (req, res) => {
  const r = await query("SELECT * FROM stock_history ORDER BY id DESC LIMIT 200");
  res.json(r.rows);
});

app.get("/api/tables", async (req, res) => {
  const r = await query("SELECT * FROM tables_bar ORDER BY name ASC");
  res.json(r.rows);
});

app.post("/api/tables", authMiddleware, async (req, res) => {
  try {
    if (!requireRole(req.user, ["admin", "cashier"])) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    const name = String(req.body.name || "").trim();

    if (!name) {
      return res.status(400).json({ error: "Nom de table obligatoire" });
    }

    const result = await query(
      "INSERT INTO tables_bar(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING *",
      [name]
    );

    await addLog(req.user, "Création table", name);

    res.json(result.rows[0]);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.delete("/api/tables/:id", authMiddleware, async (req, res) => {
  try {
    if (!requireRole(req.user, ["admin"])) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    const result = await query(
      "DELETE FROM tables_bar WHERE id=$1 RETURNING *",
      [req.params.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Table introuvable" });
    }

    await addLog(req.user, "Suppression table", result.rows[0].name);

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/waitresses", async (req, res) => {
  try {
    const result = await query(
      `SELECT id, full_name, username, role, active 
       FROM users 
       WHERE role='waitress' AND active=true
       ORDER BY full_name ASC`
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/invoices", async (req, res) => {
  const status = req.query.status;
  const params = [];
  let where = "";

  if (status) {
    params.push(status);
    where = "WHERE status=$1";
  }

  const r = await query(`SELECT * FROM invoices ${where} ORDER BY id DESC LIMIT 200`, params);
  res.json(r.rows);
});

app.get("/api/invoices/:id/items", async (req, res) => {
  const r = await query("SELECT * FROM invoice_items WHERE invoice_id=$1", [req.params.id]);
  res.json(r.rows);
});

app.post("/api/invoices", authMiddleware, async (req, res) => {
  const user = req.user;
  if (!requireRole(user, ["admin", "cashier"])) return res.status(403).json({ error: "Accès refusé" });

  const { tableName, waitressId, items } = req.body;

  const w = await query("SELECT id, full_name FROM users WHERE id=$1 AND role='waitress'", [waitressId]);
  if (w.rowCount === 0) return res.status(400).json({ error: "Serveuse invalide" });

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    let total = 0;
    const prepared = [];

    for (const it of items) {
      const pr = await client.query("SELECT * FROM products WHERE id=$1 FOR UPDATE", [it.productId]);
      if (pr.rowCount === 0) throw new Error("Produit introuvable");

      const p = pr.rows[0];
      if (Number(p.qty) < Number(it.qty)) throw new Error(`Stock insuffisant pour ${p.name}`);

      const lineTotal = Number(p.price) * Number(it.qty);
      total += lineTotal;
      prepared.push({ p, qty: Number(it.qty), lineTotal });
    }

    const count = await client.query("SELECT COUNT(*)::int AS c FROM invoices");
    const number = "FAC-" + String(count.rows[0].c + 1).padStart(5, "0");

    const inv = await client.query(
      `INSERT INTO invoices(number,table_name,waitress_id,waitress_name,cashier_id,cashier_name,total,status)
       VALUES($1,$2,$3,$4,$5,$6,$7,'unpaid') RETURNING *`,
      [number, tableName, w.rows[0].id, w.rows[0].full_name, user.id, user.full_name, total]
    );

    for (const line of prepared) {
      const before = Number(line.p.qty);
      const after = before - line.qty;

      await client.query("UPDATE products SET qty=$1 WHERE id=$2", [after, line.p.id]);

      await client.query(
        "INSERT INTO invoice_items(invoice_id,product_id,product_name,qty,price,total) VALUES($1,$2,$3,$4,$5,$6)",
        [inv.rows[0].id, line.p.id, line.p.name, line.qty, line.p.price, line.lineTotal]
      );

      await client.query(
        "INSERT INTO stock_history(product_name,before_qty,after_qty,diff_qty,action_type,user_name) VALUES($1,$2,$3,$4,$5,$6)",
        [line.p.name, before, after, -line.qty, "Vente facture", user.full_name]
      );
    }

    await client.query("COMMIT");
    await addLog(user, "Création facture", `${number} / ${total} F / ${tableName}`);
    res.json(inv.rows[0]);
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.post("/api/invoices/:id/pay", authMiddleware, async (req, res) => {
  const user = await getCurrentUser(req);
  if (!requireRole(user, ["admin", "cashier"])) return res.status(403).json({ error: "Accès refusé" });

  const { paymentMode, amountGiven } = req.body;
  const invR = await query("SELECT * FROM invoices WHERE id=$1", [req.params.id]);
  const inv = invR.rows[0];

  if (!inv || inv.status === "paid") return res.status(400).json({ error: "Facture introuvable ou déjà payée" });

  const given = paymentMode === "Espèces" ? Number(amountGiven) : Number(inv.total);
  if (given < Number(inv.total)) return res.status(400).json({ error: "Montant insuffisant" });

  const change = given - Number(inv.total);

  const r = await query(
    `UPDATE invoices SET status='paid', payment_mode=$1, amount_given=$2, change_amount=$3, paid_at=NOW()
     WHERE id=$4 RETURNING *`,
    [paymentMode, given, change, req.params.id]
  );

  await addLog(user, "Règlement facture", `${inv.number} / ${paymentMode} / ${inv.total} F`);
  res.json(r.rows[0]);
});

app.post("/api/invoices/:id/cancel", async (req, res) => {
  const user = await getCurrentUser(req);
  if (!requireRole(user, ["admin"])) return res.status(403).json({ error: "Seul Admin peut annuler" });

  const reason = (req.body.reason || "").trim();
  if (reason.length < 3) return res.status(400).json({ error: "Motif obligatoire" });

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const invR = await client.query("SELECT * FROM invoices WHERE id=$1", [req.params.id]);
    const inv = invR.rows[0];

    if (!inv || inv.status === "paid") throw new Error("Impossible d’annuler une facture payée");

    const items = await client.query("SELECT * FROM invoice_items WHERE invoice_id=$1", [inv.id]);

    for (const it of items.rows) {
      const pR = await client.query("SELECT * FROM products WHERE id=$1 FOR UPDATE", [it.product_id]);
      if (pR.rowCount) {
        const p = pR.rows[0];
        const before = Number(p.qty);
        const after = before + Number(it.qty);

        await client.query("UPDATE products SET qty=$1 WHERE id=$2", [after, p.id]);

        await client.query(
          "INSERT INTO stock_history(product_name,before_qty,after_qty,diff_qty,action_type,user_name) VALUES($1,$2,$3,$4,$5,$6)",
          [p.name, before, after, it.qty, "Annulation facture", user.full_name]
        );
      }
    }

    await client.query("DELETE FROM invoices WHERE id=$1", [inv.id]);
    await client.query("COMMIT");

    await addLog(user, "Annulation facture", `${inv.number} / Motif: ${reason}`);
    res.json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.patch("/api/invoices/:id/admin-edit", authMiddleware, async (req, res) => {
  try {
    if (!requireRole(req.user, ["admin"])) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    const {
      tableName,
      waitressId,
      paymentMode,
      amountGiven
    } = req.body;

    const invR = await query("SELECT * FROM invoices WHERE id=$1", [req.params.id]);

    if (!invR.rows.length) {
      return res.status(404).json({ error: "Facture introuvable" });
    }

    const inv = invR.rows[0];

    if (inv.status !== "paid") {
      return res.status(400).json({ error: "Cette modification concerne uniquement les factures payées" });
    }

    let waitressName = inv.waitress_name;
    let finalWaitressId = inv.waitress_id;

    if (waitressId) {
      const w = await query(
        "SELECT id, full_name FROM users WHERE id=$1 AND role='waitress'",
        [waitressId]
      );

      if (!w.rows.length) {
        return res.status(400).json({ error: "Serveuse invalide" });
      }

      finalWaitressId = w.rows[0].id;
      waitressName = w.rows[0].full_name;
    }

    const given = Number(amountGiven || inv.amount_given || inv.total);
    const change = paymentMode === "Espèces"
      ? Math.max(0, given - Number(inv.total))
      : 0;

    const result = await query(
      `UPDATE invoices
       SET table_name=$1,
           waitress_id=$2,
           waitress_name=$3,
           payment_mode=$4,
           amount_given=$5,
           change_amount=$6
       WHERE id=$7
       RETURNING *`,
      [
        tableName || inv.table_name,
        finalWaitressId,
        waitressName,
        paymentMode || inv.payment_mode,
        given,
        change,
        req.params.id
      ]
    );

    await addLog(
      req.user,
      "Modification facture payée",
      `${inv.number} / ${inv.total} F`
    );

    res.json(result.rows[0]);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur modification facture" });
  }
});

app.post("/api/closings", async (req, res) => {
  const user = await getCurrentUser(req);
  if (!requireRole(user, ["admin", "cashier"])) return res.status(403).json({ error: "Accès refusé" });

  const unpaid = await query(
    `SELECT COUNT(*)::int AS c FROM invoices WHERE status='unpaid' AND created_at::date=CURRENT_DATE ${normalizeRole(user.role) === "admin" ? "" : "AND cashier_id=$1"}`,
    normalizeRole(user.role) === "admin" ? [] : [user.id]
  );

  if (unpaid.rows[0].c > 0 && normalizeRole(user.role) !== "admin") {
    return res.status(400).json({ error: "Factures impayées restantes" });
  }

  const paid = await query(
    `SELECT * FROM invoices WHERE status='paid' AND paid_at::date=CURRENT_DATE ${normalizeRole(user.role) === "admin" ? "" : "AND cashier_id=$1"}`,
    normalizeRole(user.role) === "admin" ? [] : [user.id]
  );

  const cash = paid.rows.filter(i => i.payment_mode === "Espèces").reduce((s, i) => s + Number(i.total), 0);
  const electronic = paid.rows.filter(i => i.payment_mode !== "Espèces").reduce((s, i) => s + Number(i.total), 0);
  const total = cash + electronic;

  const r = await query(
    `INSERT INTO cash_closings(closing_date,cashier_id,cashier_name,cash_total,electronic_total,total,ticket_count,forced,unpaid_count)
     VALUES(CURRENT_DATE,$1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [user.id, user.full_name, cash, electronic, total, paid.rowCount, unpaid.rows[0].c > 0, unpaid.rows[0].c]
  );

  await addLog(user, unpaid.rows[0].c > 0 ? "Clôture forcée par Admin" : "Clôture caisse", `${user.full_name} / ${total} F`);
  res.json(r.rows[0]);
});

app.post("/api/invoices/:id/gap", authMiddleware, async (req, res) => {
  try{
    if(!requireRole(req.user, ["admin", "cashier"])){
      return res.status(403).json({ error:"Accès refusé" });
    }

    const amount = Number(req.body.amount);
    const reason = String(req.body.reason || "").trim();

    if(!amount || amount <= 0){
      return res.status(400).json({ error:"Montant écart invalide" });
    }

    if(reason.length < 3){
      return res.status(400).json({ error:"Motif obligatoire" });
    }

    const invR = await query(
      "SELECT * FROM invoices WHERE id=$1",
      [req.params.id]
    );

    if(!invR.rows.length){
      return res.status(404).json({ error:"Facture introuvable" });
    }

    const inv = invR.rows[0];

    const result = await query(
      `INSERT INTO payment_gaps
      (invoice_id, invoice_number, amount, reason, reported_by)
      VALUES($1,$2,$3,$4,$5)
      RETURNING *`,
      [
        inv.id,
        inv.number,
        amount,
        reason,
        req.user.full_name
      ]
    );

    await addLog(
      req.user,
      "Écart signalé",
      `${inv.number} / ${amount} F / ${reason}`
    );

    res.json(result.rows[0]);

  }catch(err){
    console.error(err);
    res.status(500).json({ error:"Erreur signalement écart" });
  }
});

app.post("/api/withdrawals", authMiddleware, async (req,res)=>{
  try{

    if(!requireRole(req.user, ["admin"])){
      return res.status(403).json({
        error:"Accès refusé"
      });
    }

    const amount = Number(req.body.amount);
    const reason = String(req.body.reason || "").trim();

    if(!amount || amount <= 0){
      return res.status(400).json({
        error:"Montant invalide"
      });
    }

    const result = await query(
      `INSERT INTO cash_withdrawals
      (amount, reason, created_by)
      VALUES($1,$2,$3)
      RETURNING *`,
      [
        amount,
        reason,
        req.user.full_name
      ]
    );

    await addLog(
      req.user,
      "Retrait caisse",
      amount + " F"
    );

    res.json(result.rows[0]);

  }catch(err){

    console.error(err);

    res.status(500).json({
      error:"Erreur retrait"
    });

  }
});

app.get("/api/withdrawals", authMiddleware, async (req,res)=>{

  if(!requireRole(req.user, ["admin"])){
    return res.status(403).json({
      error:"Accès refusé"
    });
  }

  const result = await query(
    `SELECT *
     FROM cash_withdrawals
     ORDER BY id DESC`
  );

  res.json(result.rows);
});

app.get("/api/closings", async (req, res) => {
  const r = await query("SELECT * FROM cash_closings ORDER BY id DESC LIMIT 200");
  res.json(r.rows);
});

app.get("/api/logs", async (req, res) => {
  const r = await query("SELECT * FROM logs ORDER BY id DESC LIMIT 200");
  res.json(r.rows);
});

app.get("/api/stats", async (req, res) => {
  const day = await query("SELECT COALESCE(SUM(total),0)::int AS total FROM invoices WHERE status='paid' AND paid_at::date=CURRENT_DATE");
  const month = await query("SELECT COALESCE(SUM(total),0)::int AS total FROM invoices WHERE status='paid' AND DATE_TRUNC('month', paid_at)=DATE_TRUNC('month', NOW())");
  const unpaid = await query("SELECT COUNT(*)::int AS c FROM invoices WHERE status='unpaid'");
  const low = await query("SELECT COUNT(*)::int AS c FROM products WHERE qty <= alert_qty");

  const top = await query(`
    SELECT product_name, SUM(qty)::int AS qty
    FROM invoice_items ii
    JOIN invoices i ON i.id=ii.invoice_id
    WHERE i.status='paid'
    GROUP BY product_name
    ORDER BY qty DESC
    LIMIT 10
  `);

 const waitressSales = await query(`
  SELECT waitress_name,
  COALESCE(SUM(total),0)::int AS total
  FROM invoices
  WHERE status='paid'
  GROUP BY waitress_name
  ORDER BY total DESC
`);

const withdrawals = await query(`
  SELECT COALESCE(SUM(amount),0)::int AS total
  FROM cash_withdrawals
`);

const allSales = await query(`
  SELECT COALESCE(SUM(total),0)::int AS total
  FROM invoices
  WHERE status='paid'
`);

const stockValue = await query(`
  SELECT COALESCE(SUM(price * qty),0)::int AS total
  FROM products
`);

const lowItems = await query(`
  SELECT name, qty, alert_qty
  FROM products
  WHERE qty <= alert_qty
  ORDER BY qty ASC, name ASC
`);

res.json({
  day: day.rows[0].total,
  month: month.rows[0].total,
  unpaid: unpaid.rows[0].c,
  lowStock: low.rows[0].c,
  lowItems: lowItems.rows,
  topProducts: top.rows,
  waitressSales: waitressSales.rows,
  withdrawals: withdrawals.rows[0].total,
  allSales: allSales.rows[0].total,
  cashBalance:
    Number(allSales.rows[0].total || 0) -
    Number(withdrawals.rows[0].total || 0),
  stockValue: stockValue.rows[0].total
});

});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`LOUNCH KOUDOUGOU AK running on port ${PORT}`));
  })
  .catch(err => {
    console.error(err);
    process.exit(1);
  });
