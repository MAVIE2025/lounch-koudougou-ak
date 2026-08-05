require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const { Pool } = require("pg");
const ExcelJS = require("exceljs");

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

// Evite qu'une connexion inactive coupee (ex: proxy Railway) ne fasse
// planter tout le process via un evenement 'error' non gere.
pool.on("error", (err) => {
  console.error("Erreur inattendue sur une connexion PG inactive:", err.message);
});

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

async function query(sql, params = []) {
  const client = await pool.connect();
  // Idem pour une connexion active coupee pendant une requete en cours.
  client.on("error", (err) => {
    console.error("Erreur inattendue sur une connexion PG active:", err.message);
  });
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

function normalizeAccountingAccess(access) {
  return String(access || "NONE")
    .trim()
    .toUpperCase();
}

function canViewAccounting(user) {
  if (!user) return false;

  if (requireRole(user, ["admin"])) {
    return true;
  }

  const access = normalizeAccountingAccess(
    user.accounting_access
  );

  return access === "READ" || access === "EDIT";
}

function canEditAccounting(user) {
  if (!user) return false;

  if (requireRole(user, ["admin"])) {
    return true;
  }

  return normalizeAccountingAccess(
    user.accounting_access
  ) === "EDIT";
}

async function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.replace("Bearer ", "").trim();

    if (!token) return res.status(401).json({ error: "Session absente" });

    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await query(
  `SELECT
     id,
     full_name,
     username,
     role,
     active,
     accounting_access
   FROM users
   WHERE id=$1
     AND active=true
   LIMIT 1`,
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
  const r = await query(
  `SELECT
     id,
     full_name,
     username,
     role,
     active,
     accounting_access
   FROM users
   WHERE id=$1`,
  [id]
);
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
  `SELECT
     id,
     full_name,
     username,
     role,
     active,
     accounting_access
   FROM users
   WHERE id=$1
     AND active=true
   LIMIT 1`,
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

    type_stock TEXT NOT NULL DEFAULT 'BOISSON'
      CHECK(type_stock IN ('BOISSON', 'NOURRITURE')),

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
  ALTER TABLE products
  ADD COLUMN IF NOT EXISTS purchase_price INTEGER
  DEFAULT 0;
`);

await query(`
  UPDATE products
  SET purchase_price = 0
  WHERE purchase_price IS NULL;
`);

await query(`
  ALTER TABLE products
  ALTER COLUMN purchase_price SET DEFAULT 0;
`);

await query(`
  ALTER TABLE products
  ALTER COLUMN purchase_price SET NOT NULL;
`);

  await query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS accounting_access TEXT
  DEFAULT 'NONE';
`);

await query(`
  UPDATE users
  SET accounting_access = CASE
    WHEN role = 'admin' THEN 'EDIT'
    ELSE 'NONE'
  END
  WHERE accounting_access IS NULL;
`);

await query(`
  ALTER TABLE users
  ALTER COLUMN accounting_access SET DEFAULT 'NONE';
`);

await query(`
  ALTER TABLE users
  ALTER COLUMN accounting_access SET NOT NULL;
`);

await query(`
  DO $$
  BEGIN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_constraint
      WHERE conname = 'users_accounting_access_check'
    ) THEN
      ALTER TABLE users
      ADD CONSTRAINT users_accounting_access_check
      CHECK(accounting_access IN ('NONE', 'READ', 'EDIT'));
    END IF;
  END
  $$;
`);

  await query(`
  ALTER TABLE products
  ADD COLUMN IF NOT EXISTS type_stock TEXT;
`);

await query(`
  UPDATE products
  SET type_stock = 'BOISSON'
  WHERE type_stock IS NULL;
`);

await query(`
  ALTER TABLE products
  ALTER COLUMN type_stock SET DEFAULT 'BOISSON';
`);

await query(`
  ALTER TABLE products
  ALTER COLUMN type_stock SET NOT NULL;
`);


await query(`
  DO $$
  BEGIN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_constraint
      WHERE conname = 'products_type_stock_check'
    ) THEN
      ALTER TABLE products
      ADD CONSTRAINT products_type_stock_check
      CHECK(type_stock IN ('BOISSON', 'NOURRITURE'));
    END IF;
  END
  $$;
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

    type_stock TEXT NOT NULL DEFAULT 'BOISSON'
      CHECK(type_stock IN ('BOISSON', 'NOURRITURE')),

    qty INTEGER NOT NULL,
    price INTEGER NOT NULL,
    total INTEGER NOT NULL
  );
`);

await query(`
  ALTER TABLE invoice_items
  ADD COLUMN IF NOT EXISTS type_stock TEXT;
`);

await query(`
  UPDATE invoice_items
  SET type_stock = COALESCE(
    (
      SELECT p.type_stock
      FROM products p
      WHERE p.id = invoice_items.product_id
    ),
    'BOISSON'
  )
  WHERE type_stock IS NULL;
`);

await query(`
  ALTER TABLE invoice_items
  ALTER COLUMN type_stock SET DEFAULT 'BOISSON';
`);

await query(`
  ALTER TABLE invoice_items
  ALTER COLUMN type_stock SET NOT NULL;
`);

await query(`
  ALTER TABLE invoice_items
  ADD COLUMN IF NOT EXISTS purchase_price INTEGER
  DEFAULT 0;
`);

await query(`
  ALTER TABLE invoice_items
  ADD COLUMN IF NOT EXISTS sale_price INTEGER
  DEFAULT 0;
`);

await query(`
  ALTER TABLE invoice_items
  ADD COLUMN IF NOT EXISTS profit INTEGER
  DEFAULT 0;
`);

await query(`
  UPDATE invoice_items
  SET sale_price = price
  WHERE sale_price IS NULL
     OR sale_price = 0;
`);

await query(`
  UPDATE invoice_items
  SET purchase_price = COALESCE(
    (
      SELECT p.purchase_price
      FROM products p
      WHERE p.id = invoice_items.product_id
    ),
    0
  )
  WHERE purchase_price IS NULL;
`);

await query(`
  UPDATE invoice_items
  SET profit =
    (
      COALESCE(sale_price, price, 0)
      - COALESCE(purchase_price, 0)
    ) * qty
  WHERE profit IS NULL;
`);

await query(`
  ALTER TABLE invoice_items
  ALTER COLUMN purchase_price SET DEFAULT 0;
`);

await query(`
  ALTER TABLE invoice_items
  ALTER COLUMN sale_price SET DEFAULT 0;
`);

await query(`
  ALTER TABLE invoice_items
  ALTER COLUMN profit SET DEFAULT 0;
`);

/*
  Migration des anciennes ventes.

  Les ventes enregistrées avant la création du module comptable
  reçoivent le prix d'achat actuellement renseigné sur le produit.
*/
await query(`
  UPDATE invoice_items ii
  SET purchase_price = COALESCE(p.purchase_price, 0)
  FROM products p
  WHERE p.id = ii.product_id
    AND COALESCE(ii.purchase_price, 0) = 0;
`);

await query(`
  UPDATE invoice_items
  SET sale_price = COALESCE(NULLIF(sale_price, 0), price, 0)
  WHERE COALESCE(sale_price, 0) = 0;
`);

await query(`
  UPDATE invoice_items
  SET profit =
    (
      COALESCE(NULLIF(sale_price, 0), price, 0)
      - COALESCE(purchase_price, 0)
    ) * COALESCE(qty, 0);
`);

await query(`
  DO $$
  BEGIN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_constraint
      WHERE conname = 'invoice_items_type_stock_check'
    ) THEN
      ALTER TABLE invoice_items
      ADD CONSTRAINT invoice_items_type_stock_check
      CHECK(type_stock IN ('BOISSON', 'NOURRITURE'));
    END IF;
  END
  $$;
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

  await query(`
  CREATE TABLE IF NOT EXISTS product_price_history (
    id SERIAL PRIMARY KEY,
    product_id INTEGER,
    product_name TEXT NOT NULL,

    old_purchase_price INTEGER DEFAULT 0,
    new_purchase_price INTEGER DEFAULT 0,

    old_sale_price INTEGER DEFAULT 0,
    new_sale_price INTEGER DEFAULT 0,

    changed_by_id INTEGER,
    changed_by_name TEXT,

    reason TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  );
`);

await query(`
  CREATE TABLE IF NOT EXISTS expenses (
    id SERIAL PRIMARY KEY,
    expense_date DATE NOT NULL DEFAULT CURRENT_DATE,
    category TEXT NOT NULL,
    description TEXT,
    amount INTEGER NOT NULL CHECK(amount > 0),
    created_by_id INTEGER,
    created_by_name TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
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
      return res.status(403).json({
        error: "Accès refusé"
      });
    }

    const {
      name,
      category,
      typeStock,
      price,
      qty,
      alertQty,
      deliveryPhoto
    } = req.body;

    if (
      !name ||
      !category ||
      !["BOISSON", "NOURRITURE"].includes(typeStock)
    ) {
      return res.status(400).json({
        error: "Nom, catégorie et type obligatoires"
      });
    }

    const old = await query(
      "SELECT * FROM products WHERE id=$1",
      [req.params.id]
    );

    if (!old.rows.length) {
      return res.status(404).json({
        error: "Produit introuvable"
      });
    }

    const before = Number(old.rows[0].qty);
    const after = Number(qty);

    const result = await query(
      `UPDATE products
       SET
         name=$1,
         category=$2,
         type_stock=$3,
         price=$4,
         qty=$5,
         alert_qty=$6,
         delivery_photo=COALESCE($7, delivery_photo),
         updated_by=$8,
         updated_at=NOW()
       WHERE id=$9
       RETURNING *`,
      [
        name,
        category,
        typeStock,
        Number(price),
        after,
        Number(alertQty),
        deliveryPhoto || null,
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
        name,
        before,
        after,
        after - before,
        "Modification",
        req.user.full_name
      ]
    );

    await addLog(
      req.user,
      "Modification produit",
      `${name} / ${typeStock}`
    );

    return res.json(result.rows[0]);

  } catch (err) {

    console.error("Erreur modification produit :", err);

    return res.status(500).json({
      error: err.message || "Erreur modification produit"
    });
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
  active: user.active,
  accountingAccess:
    user.role === "admin"
      ? "EDIT"
      : user.accounting_access || "NONE"
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
  `SELECT
     id,
     full_name,
     username,
     plain_password,
     role,
     active,
     accounting_access,
     created_at
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

  const {
    name,
    category,
    typeStock,
    price,
    qty,
    alertQty,
    deliveryPhoto
} = req.body;

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
  `INSERT INTO products
  (
    name,
    category,
    type_stock,
    price,
    qty,
    alert_qty,
    delivery_photo,
    created_by
  )
  VALUES($1,$2,$3,$4,$5,$6,$7,$8)
  RETURNING *`,
  [
    name,
    category,
    typeStock,
    price,
    qty,
    alertQty,
    deliveryPhoto || null,
    user.full_name
  ]
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
  client.on("error", (err) => {
    console.error("Erreur inattendue sur une connexion PG active:", err.message);
  });

  try {
    await client.query("BEGIN");

    let total = 0;
    const prepared = [];

    for (const it of items) {
  const pr = await client.query(
    "SELECT * FROM products WHERE id=$1 FOR UPDATE",
    [it.productId]
  );

  if (pr.rowCount === 0) {
    throw new Error("Produit introuvable");
  }

  const p = pr.rows[0];
  const quantity = Number(it.qty);

  if (Number(p.qty) < quantity) {
    throw new Error(
      `Stock insuffisant pour ${p.name}`
    );
  }

  const purchasePrice = Number(
    p.purchase_price || 0
  );

  const salePrice = Number(
    p.price || 0
  );

  const lineTotal =
    salePrice * quantity;

  const lineProfit =
    (salePrice - purchasePrice) * quantity;

  total += lineTotal;

  prepared.push({
    p,
    qty: quantity,
    purchasePrice,
    salePrice,
    lineTotal,
    lineProfit
  });
}

    const count = await client.query("SELECT COUNT(*)::int AS c FROM invoices");
    const lastInvoice = await query(`
    SELECT number
    FROM invoices
    WHERE number LIKE 'FAC-%'
    ORDER BY CAST(REPLACE(number,'FAC-','') AS INTEGER) DESC
    LIMIT 1
`);

const lastNumber = lastInvoice.rows.length
    ? Number(lastInvoice.rows[0].number.replace("FAC-",""))
    : 0;

const number = "FAC-" + String(lastNumber + 1).padStart(5,"0");

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
  `
  INSERT INTO invoice_items
  (
    invoice_id,
    product_id,
    product_name,
    type_stock,
    qty,
    price,
    purchase_price,
    sale_price,
    profit,
    total
  )
  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
  `,
  [
    inv.rows[0].id,
    line.p.id,
    line.p.name,
    line.p.type_stock || "BOISSON",
    line.qty,
    line.salePrice,
    line.purchasePrice,
    line.salePrice,
    line.lineProfit,
    line.lineTotal
  ]
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
  client.on("error", (err) => {
    console.error("Erreur inattendue sur une connexion PG active:", err.message);
  });

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

const waitressItems = await query(`
  SELECT
    i.waitress_name,
    ii.product_name,
    SUM(ii.qty)::int AS qty
  FROM invoice_items ii
  JOIN invoices i ON i.id = ii.invoice_id
  WHERE i.status = 'paid'
  GROUP BY i.waitress_name, ii.product_name
  ORDER BY i.waitress_name ASC, qty DESC
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
  waitressItems: waitressItems.rows,
  allSales: allSales.rows[0].total,
  cashBalance:
    Number(allSales.rows[0].total || 0) -
    Number(withdrawals.rows[0].total || 0),
  stockValue: stockValue.rows[0].total
});

});

function getReportPeriod(queryParams) {
  const type = String(queryParams.type || "").trim();
  const year = Number(queryParams.year);
  const month = Number(queryParams.month);
  const quarter = Number(queryParams.quarter);
  const semester = Number(queryParams.semester);
  const date = String(queryParams.date || "").trim();

  if (type === "day") {
    if (!date) {
      throw new Error("Date obligatoire");
    }

    return {
      startDate: date,
      endDate: `${date} 23:59:59.999`,
      label: `Journée du ${date}`
    };
  }

  if (!year) {
    throw new Error("Année obligatoire");
  }

  if (type === "month") {
    if (month < 1 || month > 12) {
      throw new Error("Mois invalide");
    }

    const startDate =
      `${year}-${String(month).padStart(2, "0")}-01`;

    const endDate =
      month === 12
        ? `${year + 1}-01-01`
        : `${year}-${String(month + 1).padStart(2, "0")}-01`;

    return {
      startDate,
      endDate,
      label: `Mois ${month}/${year}`
    };
  }

  if (type === "quarter") {
    if (quarter < 1 || quarter > 4) {
      throw new Error("Trimestre invalide");
    }

    const startMonth = (quarter - 1) * 3 + 1;
    const endMonth = startMonth + 3;

    const startDate =
      `${year}-${String(startMonth).padStart(2, "0")}-01`;

    const endDate =
      endMonth > 12
        ? `${year + 1}-01-01`
        : `${year}-${String(endMonth).padStart(2, "0")}-01`;

    return {
      startDate,
      endDate,
      label: `Trimestre ${quarter} - ${year}`
    };
  }

  if (type === "semester") {
    if (![1, 2].includes(semester)) {
      throw new Error("Semestre invalide");
    }

    return semester === 1
      ? {
          startDate: `${year}-01-01`,
          endDate: `${year}-07-01`,
          label: `Premier semestre ${year}`
        }
      : {
          startDate: `${year}-07-01`,
          endDate: `${year + 1}-01-01`,
          label: `Deuxième semestre ${year}`
        };
  }

  if (type === "year") {
    return {
      startDate: `${year}-01-01`,
      endDate: `${year + 1}-01-01`,
      label: `Année ${year}`
    };
  }

  throw new Error("Type de rapport invalide");
}

app.get(
  "/api/reports/transactions",
  authMiddleware,
  async (req, res) => {
    try {
      if (!canViewAccounting(req.user)) {
        return res.status(403).json({
          error: "Accès comptabilité refusé"
        });
      }

      const period = getReportPeriod(req.query);

      const result = await query(
        `
        SELECT
          i.number,
          i.created_at,
          i.paid_at,
          i.table_name,
          i.waitress_name,
          i.cashier_name,
          i.status,
          i.payment_mode,

          ii.product_name,
          ii.type_stock,
          ii.qty,

          COALESCE(
            NULLIF(ii.sale_price, 0),
            ii.price,
            0
          )::int AS sale_price,

          COALESCE(
            ii.purchase_price,
            p.purchase_price,
            0
          )::int AS purchase_price,

          ii.total::int AS line_total,

          (
            (
              COALESCE(
                NULLIF(ii.sale_price, 0),
                ii.price,
                0
              )
              -
              COALESCE(
                ii.purchase_price,
                p.purchase_price,
                0
              )
            )
            * ii.qty
          )::int AS profit

        FROM invoice_items ii

        JOIN invoices i
          ON i.id = ii.invoice_id

        LEFT JOIN products p
          ON p.id = ii.product_id

        WHERE i.status = 'paid'
          AND i.paid_at >= $1
          AND i.paid_at < $2

        ORDER BY i.paid_at ASC, i.id ASC, ii.id ASC
        `,
        [period.startDate, period.endDate]
      );

      const rows = result.rows;

      const workbook = new ExcelJS.Workbook();

      const detailSheet =
        workbook.addWorksheet("Ventes détaillées");

      detailSheet.mergeCells("A1:N1");
      detailSheet.getCell("A1").value =
        "LE DOMAINE - RAPPORT DÉTAILLÉ DES VENTES";

      detailSheet.getCell("A1").font = {
        bold: true,
        size: 16
      };

      detailSheet.getCell("A1").alignment = {
        horizontal: "center"
      };

      detailSheet.mergeCells("A2:N2");
      detailSheet.getCell("A2").value = period.label;
      detailSheet.getCell("A2").alignment = {
        horizontal: "center"
      };

      detailSheet.addRow([]);

      detailSheet.addRow([
        "Facture",
        "Date",
        "Heure",
        "Table",
        "Serveuse",
        "Caissier",
        "Produit",
        "Type",
        "Quantité",
        "Prix achat",
        "Prix vente",
        "Total vente",
        "Bénéfice",
        "Paiement"
      ]);

      rows.forEach(row => {
        const paymentDate =
          row.paid_at
            ? new Date(row.paid_at)
            : new Date(row.created_at);

        detailSheet.addRow([
          row.number,
          paymentDate.toLocaleDateString("fr-FR"),
          paymentDate.toLocaleTimeString("fr-FR"),
          row.table_name || "",
          row.waitress_name || "",
          row.cashier_name || "",
          row.product_name || "",
          row.type_stock || "",
          Number(row.qty || 0),
          Number(row.purchase_price || 0),
          Number(row.sale_price || 0),
          Number(row.line_total || 0),
          Number(row.profit || 0),
          row.payment_mode || ""
        ]);
      });

      detailSheet.getRow(4).font = {
        bold: true
      };

      detailSheet.columns.forEach(column => {
        column.width = 18;
      });

      const accountingSheet =
        workbook.addWorksheet("Comptabilité");

      accountingSheet.addRow([
        "Produit",
        "Quantité vendue",
        "Chiffre d'affaires",
        "Coût d'achat",
        "Bénéfice"
      ]);

      const grouped = {};

      rows.forEach(row => {
        const key = row.product_name || "Produit inconnu";

        if (!grouped[key]) {
          grouped[key] = {
            productName: key,
            qty: 0,
            revenue: 0,
            cost: 0,
            profit: 0
          };
        }

        grouped[key].qty += Number(row.qty || 0);
        grouped[key].revenue +=
          Number(row.line_total || 0);

        grouped[key].cost +=
          Number(row.purchase_price || 0) *
          Number(row.qty || 0);

        grouped[key].profit +=
          Number(row.profit || 0);
      });

      Object.values(grouped).forEach(item => {
        accountingSheet.addRow([
          item.productName,
          item.qty,
          item.revenue,
          item.cost,
          item.profit
        ]);
      });

      const totalRevenue = rows.reduce(
        (sum, row) =>
          sum + Number(row.line_total || 0),
        0
      );

      const totalCost = rows.reduce(
        (sum, row) =>
          sum +
          Number(row.purchase_price || 0) *
          Number(row.qty || 0),
        0
      );

      const totalProfit = totalRevenue - totalCost;

      accountingSheet.addRow([]);
      accountingSheet.addRow([
        "TOTAL",
        "",
        totalRevenue,
        totalCost,
        totalProfit
      ]);

      accountingSheet.getRow(1).font = {
        bold: true
      };

      accountingSheet.columns.forEach(column => {
        column.width = 24;
      });

      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      );

      res.setHeader(
        "Content-Disposition",
        `attachment; filename="rapport_comptabilite_${req.query.type || "periode"}.xlsx"`
      );

      await workbook.xlsx.write(res);
      res.end();

    } catch (err) {
      console.error(
        "Erreur rapport comptabilité :",
        err
      );

      res.status(500).json({
        error:
          err.message ||
          "Erreur génération du rapport"
      });
    }
  }
);

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
