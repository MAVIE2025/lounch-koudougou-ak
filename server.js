require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

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
      "INSERT INTO users(full_name, username, password_hash, plain_password, role) VALUES($1,$2,$3,$4,$5)",
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

async function addLog(user, action, details = "") {
  await query(
    "INSERT INTO logs(user_name, role, action, details) VALUES($1,$2,$3,$4)",
    [user?.full_name || "Système", user?.role || "system", action, details]
  );
}

async function getUserFromHeader(req) {
  const id = req.headers["x-user-id"];
  if (!id) return null;
  const r = await query("SELECT id, full_name, username, role, active FROM users WHERE id=$1", [id]);
  return r.rows[0] || null;
}

function requireRole(user, roles) {
  return user && user.active !== false && roles.includes(user.role);
}

app.get("/api/health", (req, res) => res.json({ ok: true, app: "LOUNCH KOUDOUGOU AK" }));

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const r = await query("SELECT * FROM users WHERE username=$1 AND active=true", [username]);
  const user = r.rows[0];
  if (!user) return res.status(401).json({ error: "Identifiants incorrects" });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Identifiants incorrects" });
  await addLog(user, "Connexion", "Connexion au logiciel");
  res.json({ id: user.id, fullName: user.full_name, username: user.username, role: user.role });
});

app.get("/api/users", async (req, res) => {
  const user = await getUserFromHeader(req);
  if (!requireRole(user, ["admin"])) return res.status(403).json({ error: "Accès refusé" });
  const r = await query("SELECT id, full_name, username, plain_password, role, active, created_at FROM users ORDER BY id DESC");
  res.json(r.rows);
});

app.post("/api/users", async (req, res) => {
  const user = await getUserFromHeader(req);
  if (!requireRole(user, ["admin"])) return res.status(403).json({ error: "Accès refusé" });
  const { fullName, username, password, role } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const r = await query(
    "INSERT INTO users(full_name, username, password_hash, plain_password, role) VALUES($1,$2,$3,$4,$5) RETURNING *",
    [fullName, username, hash, password, role]
  );
  await addLog(user, "Création utilisateur", `${fullName} (${role})`);
  res.json(r.rows[0]);
});

app.put("/api/users/:id", async (req, res) => {
  const user = await getUserFromHeader(req);
  if (!requireRole(user, ["admin"])) return res.status(403).json({ error: "Accès refusé" });
  const { fullName, username, password, role, active } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const r = await query(
    "UPDATE users SET full_name=$1, username=$2, password_hash=$3, plain_password=$4, role=$5, active=$6 WHERE id=$7 RETURNING *",
    [fullName, username, hash, password, role, active, req.params.id]
  );
  await addLog(user, "Modification utilisateur", `${fullName} (${role})`);
  res.json(r.rows[0]);
});

app.get("/api/products", async (req, res) => {
  const r = await query("SELECT * FROM products ORDER BY name ASC");
  res.json(r.rows);
});

app.post("/api/products", async (req, res) => {
  const user = await getUserFromHeader(req);
  if (!requireRole(user, ["admin", "storekeeper"])) return res.status(403).json({ error: "Accès refusé" });

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
      `UPDATE products SET category=$1, price=$2, qty=$3, alert_qty=$4, delivery_photo=COALESCE($5, delivery_photo), updated_by=$6, updated_at=NOW()
       WHERE id=$7 RETURNING *`,
      [category, user.role === "admin" ? price : p.price, after, user.role === "admin" ? alertQty : p.alert_qty, deliveryPhoto || null, user.full_name, p.id]
    );
    await query(
      "INSERT INTO stock_history(product_name,before_qty,after_qty,diff_qty,action_type,user_name) VALUES($1,$2,$3,$4,$5,$6)",
      [p.name, before, after, Number(qty), "Réapprovisionnement", user.full_name]
    );
    await addLog(user, "Réapprovisionnement stock", `${p.name} +${qty}`);
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
  await addLog(user, "Création item stock", `${name} / quantité ${qty}`);
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

app.post("/api/tables", async (req, res) => {
  const user = await getUserFromHeader(req);
  if (!requireRole(user, ["admin", "cashier"])) return res.status(403).json({ error: "Accès refusé" });
  const r = await query("INSERT INTO tables_bar(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING *", [req.body.name]);
  await addLog(user, "Création table", req.body.name);
  res.json(r.rows[0]);
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

app.post("/api/invoices", async (req, res) => {
  const user = await getUserFromHeader(req);
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

app.post("/api/invoices/:id/pay", async (req, res) => {
  const user = await getUserFromHeader(req);
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
  const user = await getUserFromHeader(req);
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

app.post("/api/closings", async (req, res) => {
  const user = await getUserFromHeader(req);
  if (!requireRole(user, ["admin", "cashier"])) return res.status(403).json({ error: "Accès refusé" });

  const unpaid = await query(
    `SELECT COUNT(*)::int AS c FROM invoices WHERE status='unpaid' AND created_at::date=CURRENT_DATE ${user.role === "admin" ? "" : "AND cashier_id=$1"}`,
    user.role === "admin" ? [] : [user.id]
  );

  if (unpaid.rows[0].c > 0 && user.role !== "admin") {
    return res.status(400).json({ error: "Factures impayées restantes" });
  }

  const paid = await query(
    `SELECT * FROM invoices WHERE status='paid' AND paid_at::date=CURRENT_DATE ${user.role === "admin" ? "" : "AND cashier_id=$1"}`,
    user.role === "admin" ? [] : [user.id]
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
  res.json({ day: day.rows[0].total, month: month.rows[0].total, unpaid: unpaid.rows[0].c, lowStock: low.rows[0].c, topProducts: top.rows });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDb().then(() => {
  app.listen(PORT, () => console.log(`LOUNCH KOUDOUGOU AK running on port ${PORT}`));
}).catch(err => {
  console.error(err);
  process.exit(1);
});