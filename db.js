// =========================================================================
// TOKYO DRIFT — PERSISTENT CLOUD & LOCAL DATABASE ADAPTER
// Supports PostgreSQL (Supabase / Neon / Vercel Postgres) + SQLite / JSON fallback
// All PostgreSQL tables are namespaced with 'td_' prefix for isolation
// =========================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Load .env.local if present in development
if (fs.existsSync(path.join(__dirname, '.env.local'))) {
  try {
    const envContent = fs.readFileSync(path.join(__dirname, '.env.local'), 'utf8');
    for (const line of envContent.split('\n')) {
      const match = line.match(/^([^=]+)=(.*)$/);
      if (match) {
        const k = match[1].trim();
        const v = match[2].trim().replace(/^["']|["']$/g, '');
        if (!process.env[k]) process.env[k] = v;
      }
    }
  } catch(e) {}
}

let pgPool = null;
let sqliteDb = null;
const JSON_DB_PATH = path.join(__dirname, 'database.json');

// Check PostgreSQL availability
let pgHost = process.env.POSTGRES_HOST;
let pgDatabase = process.env.POSTGRES_DATABASE || 'postgres';
let pgUser = process.env.POSTGRES_USER || 'postgres';
let pgPassword = process.env.POSTGRES_PASSWORD;
let pgPort = parseInt(process.env.POSTGRES_PORT || '5432', 10);

const candidateUrl = process.env.POSTGRES_URL || process.env.POSTGRES_PRISMA_URL || process.env.POSTGRES_URL_NON_POOLING;
if (candidateUrl) {
  try {
    const u = new URL(candidateUrl);
    pgHost = u.hostname;
    pgPort = parseInt(u.port || '5432', 10);
    pgDatabase = u.pathname.replace(/^\//, '') || pgDatabase;
    pgUser = decodeURIComponent(u.username) || pgUser;
    pgPassword = decodeURIComponent(u.password) || pgPassword;
  } catch(e) {}
}

// In serverless environments, connect to Supabase PgBouncer transaction pooler on 6543 to eliminate connection limits
if (pgHost && pgHost.includes('pooler.supabase.com')) {
  pgPort = 6543;
}

if (!global._tdPgPool && pgHost && pgPassword) {
  try {
    const { Pool } = require('pg');
    const maxPool = parseInt(process.env.PG_MAX_POOL || (process.env.VERCEL ? '4' : '10'), 10);
    global._tdPgPool = new Pool({
      host: pgHost,
      port: pgPort,
      database: pgDatabase,
      user: pgUser,
      password: pgPassword,
      ssl: { rejectUnauthorized: false },
      max: maxPool,
      idleTimeoutMillis: 10000,
      connectionTimeoutMillis: 15000,
      statement_timeout: 15000
    });
    global._tdPgPool.on('error', (err) => {
      console.warn('[Tokyo Drift DB] Pool idle client dropped or reset:', err.message);
    });
    console.log('[Tokyo Drift DB] PostgreSQL Cloud Pool connected:', `${pgHost}:${pgPort}/${pgDatabase} (Transaction Mode)`);
  } catch (err) {
    console.warn('[Tokyo Drift DB] Could not initialize PostgreSQL pool:', err.message);
  }
}
pgPool = global._tdPgPool || null;

// Fallback SQLite initialization
if (!pgPool) {
  const isVercel = process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME;
  let dbPath = path.join(__dirname, 'database.sqlite');
  if (isVercel) {
    const tmpPath = path.join('/tmp', 'database.sqlite');
    try {
      if (!fs.existsSync(tmpPath) && fs.existsSync(dbPath)) {
        fs.copyFileSync(dbPath, tmpPath);
      }
      dbPath = tmpPath;
    } catch(e) {}
  }
  try {
    const sqlite = require('node:sqlite');
    if (sqlite && sqlite.DatabaseSync) {
      sqliteDb = new sqlite.DatabaseSync(dbPath);
      console.log('[Tokyo Drift DB] SQLite fallback active:', dbPath);
    }
  } catch(e) {
    console.warn('[Tokyo Drift DB] SQLite unavailable (' + e.message + '), falling back to JSON file.');
  }
}

async function init() {
  if (pgPool) {
    try {
      await pgPool.query(`
        CREATE TABLE IF NOT EXISTS td_products (
          id TEXT PRIMARY KEY,
          title TEXT,
          collection TEXT,
          category TEXT,
          price NUMERIC,
          badge TEXT,
          edition TEXT,
          "shortDesc" TEXT,
          description TEXT,
          composition TEXT,
          care TEXT,
          "primaryImage" TEXT,
          "altImage" TEXT,
          sizes JSONB,
          stock JSONB,
          created_at TEXT,
          gallery JSONB,
          colors JSONB
        );

        CREATE TABLE IF NOT EXISTS td_orders (
          id TEXT PRIMARY KEY,
          date TEXT,
          status TEXT,
          "trackingNumber" TEXT,
          carrier TEXT,
          customer JSONB,
          items JSONB,
          financials JSONB,
          payment JSONB,
          created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS td_settings (
          key TEXT PRIMARY KEY,
          value JSONB
        );

        CREATE TABLE IF NOT EXISTS td_categories (
          name TEXT PRIMARY KEY
        );

        CREATE TABLE IF NOT EXISTS td_promos (
          code TEXT PRIMARY KEY,
          discount INTEGER,
          note TEXT
        );

        CREATE TABLE IF NOT EXISTS td_reviews (
          id TEXT PRIMARY KEY,
          "productId" TEXT,
          "customerName" TEXT,
          rating INTEGER,
          "fitFeedback" TEXT,
          "reviewTitle" TEXT,
          comment TEXT,
          "verifiedPurchase" BOOLEAN,
          date TEXT
        );

        CREATE TABLE IF NOT EXISTS td_subscribers (
          email TEXT PRIMARY KEY,
          date TEXT
        );

        CREATE TABLE IF NOT EXISTS td_restock_alerts (
          id TEXT PRIMARY KEY,
          "productId" TEXT,
          size TEXT,
          email TEXT,
          date TEXT
        );

        CREATE TABLE IF NOT EXISTS td_appointments (
          id TEXT PRIMARY KEY,
          "clientName" TEXT,
          email TEXT,
          phone TEXT,
          city TEXT,
          "preferredDate" TEXT,
          "stylingInterests" TEXT,
          status TEXT,
          created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS td_customers (
          id TEXT PRIMARY KEY,
          name TEXT,
          email TEXT UNIQUE,
          "passwordHash" TEXT,
          phone TEXT,
          address TEXT,
          city TEXT,
          "postalCode" TEXT,
          country TEXT,
          created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS td_customer_sessions (
          token TEXT PRIMARY KEY,
          "customerId" TEXT,
          created_at TEXT,
          expires_at TEXT
        );

        CREATE TABLE IF NOT EXISTS td_page_views (
          id BIGSERIAL PRIMARY KEY,
          path TEXT,
          referrer TEXT,
          device TEXT,
          ip TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS td_uploads (
          id TEXT PRIMARY KEY,
          filename TEXT,
          mime TEXT,
          data TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS td_bank_credits (
          utr TEXT PRIMARY KEY,
          amount NUMERIC(10,2) NOT NULL,
          sender TEXT,
          claimed_by_order TEXT,
          raw TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        -- Ensure modern columns
        ALTER TABLE td_page_views ADD COLUMN IF NOT EXISTS ip TEXT;
        ALTER TABLE td_page_views ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
        ALTER TABLE td_customers ADD COLUMN IF NOT EXISTS "passwordHash" TEXT;
        ALTER TABLE td_customers ADD COLUMN IF NOT EXISTS address TEXT;
        ALTER TABLE td_customers ADD COLUMN IF NOT EXISTS city TEXT;
        ALTER TABLE td_customers ADD COLUMN IF NOT EXISTS "postalCode" TEXT;
        ALTER TABLE td_customers ADD COLUMN IF NOT EXISTS country TEXT;
        ALTER TABLE td_customer_sessions ADD COLUMN IF NOT EXISTS "customerId" TEXT;
        ALTER TABLE td_customer_sessions ADD COLUMN IF NOT EXISTS created_at TEXT;
        ALTER TABLE td_customer_sessions ADD COLUMN IF NOT EXISTS expires_at TEXT;
        ALTER TABLE td_appointments ADD COLUMN IF NOT EXISTS created_at TEXT;

        -- Essential performance indexes for scale
        CREATE INDEX IF NOT EXISTS idx_td_page_views_created ON td_page_views(created_at);
        CREATE INDEX IF NOT EXISTS idx_td_page_views_path ON td_page_views(path);
        CREATE INDEX IF NOT EXISTS idx_td_orders_created ON td_orders(created_at);
        CREATE INDEX IF NOT EXISTS idx_td_customer_sessions_tok ON td_customer_sessions(token);
        CREATE INDEX IF NOT EXISTS idx_td_customers_email ON td_customers(LOWER(email));
        CREATE INDEX IF NOT EXISTS idx_td_reviews_prod ON td_reviews("productId");
      `);
      console.log('[Tokyo Drift DB] PostgreSQL tables verified.');
    } catch (err) {
      console.error('[Tokyo Drift DB] PostgreSQL table init error:', err.message);
    }
  } else if (sqliteDb) {
    try {
      sqliteDb.exec(`
        CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, title TEXT, collection TEXT, category TEXT, price REAL, badge TEXT, edition TEXT, shortDesc TEXT, description TEXT, composition TEXT, care TEXT, primaryImage TEXT, altImage TEXT, sizes TEXT, stock TEXT, created_at TEXT, gallery TEXT, colors TEXT);
        CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, date TEXT, status TEXT, trackingNumber TEXT, carrier TEXT, customer TEXT, items TEXT, financials TEXT, payment TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS categories (name TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS promos (code TEXT PRIMARY KEY, discount INTEGER, note TEXT);
        CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, productId TEXT, customerName TEXT, rating INTEGER, fitFeedback TEXT, reviewTitle TEXT, comment TEXT, verifiedPurchase INTEGER, date TEXT);
        CREATE TABLE IF NOT EXISTS subscribers (email TEXT PRIMARY KEY, date TEXT);
        CREATE TABLE IF NOT EXISTS restock_alerts (id TEXT PRIMARY KEY, productId TEXT, size TEXT, email TEXT, date TEXT);
        CREATE TABLE IF NOT EXISTS appointments (id TEXT PRIMARY KEY, clientName TEXT, email TEXT, phone TEXT, city TEXT, preferredDate TEXT, stylingInterests TEXT, status TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS customers (id TEXT PRIMARY KEY, name TEXT, email TEXT UNIQUE, passwordHash TEXT, phone TEXT, address TEXT, city TEXT, postalCode TEXT, country TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS customer_sessions (token TEXT PRIMARY KEY, customerId TEXT, created_at TEXT, expires_at TEXT);
        CREATE TABLE IF NOT EXISTS page_views (id TEXT PRIMARY KEY, path TEXT, referrer TEXT, device TEXT, ip TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS bank_credits (utr TEXT PRIMARY KEY, amount REAL, sender TEXT, claimed_by_order TEXT, raw TEXT, created_at TEXT);
      `);
    } catch(e) {}
  }
}

// -------------------------------------------------------------------------
// PRODUCTS API
// -------------------------------------------------------------------------
async function getProducts() {
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM td_products ORDER BY id DESC');
      return res.rows.map(p => ({
        id: p.id,
        title: p.title,
        collection: p.collection,
        category: p.category,
        price: Number(p.price),
        badge: p.badge,
        edition: p.edition,
        shortDesc: p.shortDesc,
        description: p.description,
        composition: p.composition,
        care: p.care,
        primaryImage: p.primaryImage,
        altImage: p.altImage,
        sizes: Array.isArray(p.sizes) ? p.sizes : (typeof p.sizes === 'string' ? JSON.parse(p.sizes) : []),
        stock: p.stock && typeof p.stock === 'object' ? p.stock : (typeof p.stock === 'string' ? JSON.parse(p.stock) : {}),
        created_at: p.created_at,
        gallery: Array.isArray(p.gallery) ? p.gallery : (typeof p.gallery === 'string' ? JSON.parse(p.gallery) : [p.primaryImage, p.altImage].filter(Boolean)),
        colors: Array.isArray(p.colors) ? p.colors : (typeof p.colors === 'string' ? JSON.parse(p.colors) : [])
      }));
    } catch(e) {
      console.error('[DB] getProducts PG error:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT * FROM products ORDER BY rowid DESC').all().map(p => ({
        ...p,
        price: Number(p.price),
        sizes: p.sizes ? JSON.parse(p.sizes) : [],
        stock: p.stock ? JSON.parse(p.stock) : {},
        colors: p.colors ? JSON.parse(p.colors) : [],
        gallery: p.gallery ? JSON.parse(p.gallery) : [p.primaryImage, p.altImage].filter(Boolean)
      }));
    } catch(e) {}
  }

  try {
    const raw = JSON.parse(fs.readFileSync(JSON_DB_PATH, 'utf8'));
    return raw.products || [];
  } catch(e) {
    return [];
  }
}

async function saveProduct(prod) {
  const gal = Array.isArray(prod.gallery) && prod.gallery.length > 0 ? prod.gallery : [prod.primaryImage, prod.altImage].filter(Boolean);
  const cols = Array.isArray(prod.colors) ? prod.colors : [];
  const sizes = Array.isArray(prod.sizes) ? prod.sizes : [];
  const stock = prod.stock && typeof prod.stock === 'object' ? prod.stock : {};

  if (pgPool) {
    try {
      await pgPool.query(`
        INSERT INTO td_products (
          id, title, collection, category, price, badge, edition, "shortDesc",
          description, composition, care, "primaryImage", "altImage",
          sizes, stock, created_at, gallery, colors
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
        ON CONFLICT (id) DO UPDATE SET
          title = EXCLUDED.title,
          collection = EXCLUDED.collection,
          category = EXCLUDED.category,
          price = EXCLUDED.price,
          badge = EXCLUDED.badge,
          edition = EXCLUDED.edition,
          "shortDesc" = EXCLUDED."shortDesc",
          description = EXCLUDED.description,
          composition = EXCLUDED.composition,
          care = EXCLUDED.care,
          "primaryImage" = EXCLUDED."primaryImage",
          "altImage" = EXCLUDED."altImage",
          sizes = EXCLUDED.sizes,
          stock = EXCLUDED.stock,
          gallery = EXCLUDED.gallery,
          colors = EXCLUDED.colors
      `, [
        prod.id, prod.title || '', prod.collection || 'Outerwear', prod.category || 'outerwear',
        Number(prod.price) || 0, prod.badge || '', prod.edition || '', prod.shortDesc || '',
        prod.description || '', prod.composition || '', prod.care || '', prod.primaryImage || '', prod.altImage || '',
        JSON.stringify(sizes), JSON.stringify(stock), prod.created_at || new Date().toISOString(),
        JSON.stringify(gal), JSON.stringify(cols)
      ]);
      return { success: true, product: prod };
    } catch(e) {
      console.error('[DB] saveProduct PG error:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      sqliteDb.prepare(`
        INSERT OR REPLACE INTO products (id, title, collection, category, price, badge, edition, shortDesc, description, composition, care, primaryImage, altImage, sizes, stock, created_at, gallery, colors)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        prod.id, prod.title || '', prod.collection || 'Outerwear', prod.category || 'outerwear',
        Number(prod.price) || 0, prod.badge || '', prod.edition || '', prod.shortDesc || '',
        prod.description || '', prod.composition || '', prod.care || '', prod.primaryImage || '', prod.altImage || '',
        JSON.stringify(sizes), JSON.stringify(stock), prod.created_at || new Date().toISOString(),
        JSON.stringify(gal), JSON.stringify(cols)
      );
    } catch(e) {}
  }

  return { success: true, product: prod };
}

async function deleteProduct(id) {
  if (pgPool) {
    try {
      await pgPool.query('DELETE FROM td_products WHERE id = $1', [id]);
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('DELETE FROM products WHERE id = ?').run(id);
    } catch(e) {}
  }
  return { success: true, id };
}

// -------------------------------------------------------------------------
// ORDERS API
// -------------------------------------------------------------------------
async function getOrders() {
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM td_orders ORDER BY created_at DESC');
      return res.rows.map(o => ({
        id: o.id,
        date: o.date,
        status: o.status,
        trackingNumber: o.trackingNumber || `TKD-TRK-${o.id.replace('TKD-', '')}`,
        carrier: o.carrier || 'Yamato Transport / DHL Express',
        customer: typeof o.customer === 'string' ? JSON.parse(o.customer) : (o.customer || {}),
        items: typeof o.items === 'string' ? JSON.parse(o.items) : (o.items || []),
        financials: typeof o.financials === 'string' ? JSON.parse(o.financials) : (o.financials || {}),
        payment: typeof o.payment === 'string' ? JSON.parse(o.payment) : (o.payment || {})
      }));
    } catch(e) {
      console.error('[DB] getOrders PG error:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT * FROM orders ORDER BY rowid DESC').all().map(o => ({
        id: o.id,
        date: o.date,
        status: o.status,
        trackingNumber: o.trackingNumber || `TKD-TRK-${o.id.replace('TKD-', '')}`,
        carrier: o.carrier || 'Yamato Transport / DHL Express',
        customer: o.customer ? JSON.parse(o.customer) : {},
        items: o.items ? JSON.parse(o.items) : [],
        financials: o.financials ? JSON.parse(o.financials) : {},
        payment: o.payment ? JSON.parse(o.payment) : {}
      }));
    } catch(e) {}
  }

  return [];
}

async function saveOrder(order) {
  const trk = order.trackingNumber || ('TKD-' + Math.floor(10000000 + Math.random() * 90000000));
  const dateStr = order.date || new Date().toISOString();

  if (pgPool) {
    try {
      await pgPool.query(`
        INSERT INTO td_orders (id, date, status, "trackingNumber", carrier, customer, items, financials, payment, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (id) DO UPDATE SET
          date = EXCLUDED.date,
          status = EXCLUDED.status,
          "trackingNumber" = EXCLUDED."trackingNumber",
          carrier = EXCLUDED.carrier,
          customer = EXCLUDED.customer,
          items = EXCLUDED.items,
          financials = EXCLUDED.financials,
          payment = EXCLUDED.payment
      `, [
        order.id, dateStr, order.status || 'Authorized', trk,
        order.carrier || 'Yamato Transport / DHL Express',
        JSON.stringify(order.customer || {}), JSON.stringify(order.items || []),
        JSON.stringify(order.financials || {}), JSON.stringify(order.payment || {}),
        dateStr
      ]);

      // Deduct inventory safely
      if (Array.isArray(order.items)) {
        for (const it of order.items) {
          try {
            const row = await pgPool.query('SELECT stock FROM td_products WHERE id = $1', [it.id]);
            if (row.rows[0] && row.rows[0].stock) {
              const stockObj = typeof row.rows[0].stock === 'string' ? JSON.parse(row.rows[0].stock) : row.rows[0].stock;
              if (stockObj && stockObj[it.size] !== undefined) {
                stockObj[it.size] = Math.max(0, (Number(stockObj[it.size]) || 0) - (Number(it.quantity) || 1));
                await pgPool.query('UPDATE td_products SET stock = $1 WHERE id = $2', [JSON.stringify(stockObj), it.id]);
              }
            }
          } catch(err) {
            console.error('[DB] Inventory deduct error for product:', it.id, err.message);
          }
        }
      }
      return { success: true, order: { ...order, trackingNumber: trk } };
    } catch(e) {
      console.error('[DB] saveOrder PG error:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      sqliteDb.prepare(`
        INSERT INTO orders (id, date, status, trackingNumber, carrier, customer, items, financials, payment, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        order.id, dateStr, order.status || 'Authorized', trk,
        order.carrier || 'Yamato Transport / DHL Express',
        JSON.stringify(order.customer || {}), JSON.stringify(order.items || []),
        JSON.stringify(order.financials || {}), JSON.stringify(order.payment || {}),
        dateStr
      );

      if (Array.isArray(order.items)) {
        order.items.forEach(it => {
          const row = sqliteDb.prepare('SELECT stock FROM products WHERE id = ?').get(it.id);
          if (row && row.stock) {
            try {
              const stockObj = JSON.parse(row.stock);
              if (stockObj[it.size] !== undefined) {
                stockObj[it.size] = Math.max(0, stockObj[it.size] - it.quantity);
                sqliteDb.prepare('UPDATE products SET stock = ? WHERE id = ?').run(JSON.stringify(stockObj), it.id);
              }
            } catch(e) {}
          }
        });
      }
    } catch(e) {}
  }

  return { success: true, order: { ...order, trackingNumber: trk } };
}

async function updateOrder(id, { status, carrier, trackingNumber }) {
  if (pgPool) {
    try {
      if (status && carrier && trackingNumber) {
        await pgPool.query('UPDATE td_orders SET status = $1, carrier = $2, "trackingNumber" = $3 WHERE id = $4', [status, carrier, trackingNumber, id]);
      } else if (status) {
        await pgPool.query('UPDATE td_orders SET status = $1 WHERE id = $2', [status, id]);
      }
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      if (status && carrier && trackingNumber) {
        sqliteDb.prepare('UPDATE orders SET status = ?, carrier = ?, trackingNumber = ? WHERE id = ?').run(status, carrier, trackingNumber, id);
      } else if (status) {
        sqliteDb.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, id);
      }
    } catch(e) {}
  }
  return { success: true, id };
}

async function deleteOrder(id) {
  if (pgPool) {
    try {
      await pgPool.query('DELETE FROM td_orders WHERE id = $1', [id]);
    } catch(e) {
      console.error('[DB] deleteOrder PG error:', e.message);
    }
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('DELETE FROM orders WHERE id = ?').run(id);
    } catch(e) {}
  }
  return { success: true, id };
}

async function getTracking(orderId) {
  let order = null;
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM td_orders WHERE UPPER(id) = UPPER($1)', [orderId]);
      if (res.rows[0]) order = res.rows[0];
    } catch(e) {}
  }
  if (!order && sqliteDb) {
    try {
      order = sqliteDb.prepare('SELECT * FROM orders WHERE UPPER(id) = ?').get(orderId.toUpperCase());
    } catch(e) {}
  }

  if (!order) return null;

  return {
    orderId: order.id,
    status: order.status,
    carrier: order.carrier || 'Yamato Transport / DHL Express',
    trackingNumber: order.trackingNumber || `TKD-TRK-${order.id.replace('TKD-', '')}`,
    steps: [
      { step: 'Order Acquired & Encrypted', date: order.date, completed: true },
      { step: 'Archival Atelier Tailoring & Quality Inspection', date: new Date(new Date(order.date).getTime() + 3600000).toISOString(), completed: true },
      { step: 'Courier Handover (Yamato Express)', date: new Date(new Date(order.date).getTime() + 86400000).toISOString(), completed: order.status !== 'Authorized' },
      { step: 'Out for Global Delivery', date: 'Expected within 48h', completed: order.status === 'Delivered' }
    ]
  };
}

// -------------------------------------------------------------------------
// SETTINGS API
// -------------------------------------------------------------------------
async function getSettings() {
  const decorateSettings = (s) => {
    const obj = s || {};
    if (!obj.youpiVpa) obj.youpiVpa = 'agarawalrishav23@okaxis';
    if (!obj.youpiPayeeName) obj.youpiPayeeName = 'Rishav Kumar';
    if (obj.enableYoupiUpi === undefined) obj.enableYoupiUpi = true;
    if (obj.youpiAutoApproveUtr === undefined) obj.youpiAutoApproveUtr = true;
    if (!obj.codUpiId || obj.codUpiId === 'tokyodrift@upi') obj.codUpiId = 'agarawalrishav23@okaxis';
    return obj;
  };

  const settings = {};
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT key, value FROM td_settings');
      res.rows.forEach(r => {
        try {
          settings[r.key] = typeof r.value === 'string' ? JSON.parse(r.value) : r.value;
        } catch(e) {
          settings[r.key] = r.value;
        }
      });
      return decorateSettings(settings);
    } catch(e) {
      console.error('[DB] getSettings PG error:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      const rows = sqliteDb.prepare('SELECT * FROM settings').all();
      rows.forEach(s => {
        try { settings[s.key] = JSON.parse(s.value); } catch(e) { settings[s.key] = s.value; }
      });
      return decorateSettings(settings);
    } catch(e) {}
  }

  try {
    const raw = JSON.parse(fs.readFileSync(JSON_DB_PATH, 'utf8'));
    return decorateSettings(raw.settings || {});
  } catch(e) {
    return decorateSettings({});
  }
}

async function recordBankCredit({ utr, amount, sender, raw }) {
  if (!utr) return { success: false };
  const cleanUtr = String(utr).trim();
  const numAmount = Number(amount) || 0;
  if (pgPool) {
    try {
      await pgPool.query(
        `INSERT INTO td_bank_credits (utr, amount, sender, raw, created_at)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT (utr) DO UPDATE SET amount = EXCLUDED.amount, raw = EXCLUDED.raw`,
        [cleanUtr, numAmount, sender || '', raw || '']
      );
      return { success: true, utr: cleanUtr, amount: numAmount };
    } catch(e) {
      console.warn('[DB] recordBankCredit PG error:', e.message);
    }
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare(`INSERT OR REPLACE INTO bank_credits (utr, amount, sender, claimed_by_order, raw, created_at) VALUES (?, ?, ?, NULL, ?, ?)`).run(cleanUtr, numAmount, sender || '', raw || '', new Date().toISOString());
      return { success: true, utr: cleanUtr, amount: numAmount };
    } catch(e) {}
  }
  return { success: true, utr: cleanUtr, amount: numAmount };
}

async function checkBankCredit({ amount, utr }) {
  const numAmount = Number(amount);
  if (pgPool) {
    try {
      if (utr) {
        const res = await pgPool.query('SELECT * FROM td_bank_credits WHERE utr = $1', [utr.trim()]);
        if (res.rows && res.rows.length > 0) return { found: true, credit: res.rows[0] };
      }
      if (numAmount > 0) {
        const res = await pgPool.query(
          "SELECT * FROM td_bank_credits WHERE amount = $1 AND claimed_by_order IS NULL AND created_at >= NOW() - INTERVAL '30 minutes' ORDER BY created_at DESC LIMIT 1",
          [numAmount]
        );
        if (res.rows && res.rows.length > 0) return { found: true, credit: res.rows[0] };
      }
    } catch(e) {
      console.warn('[DB] checkBankCredit PG error:', e.message);
    }
  }
  if (sqliteDb) {
    try {
      if (utr) {
        const row = sqliteDb.prepare('SELECT * FROM bank_credits WHERE utr = ?').get(utr.trim());
        if (row) return { found: true, credit: row };
      }
      if (numAmount > 0) {
        const row = sqliteDb.prepare("SELECT * FROM bank_credits WHERE amount = ? AND claimed_by_order IS NULL ORDER BY created_at DESC LIMIT 1").get(numAmount);
        if (row) return { found: true, credit: row };
      }
    } catch(e) {}
  }
  return { found: false };
}

async function claimBankCredit(utr, orderId) {
  if (!utr || !orderId) return;
  if (pgPool) {
    try {
      await pgPool.query('UPDATE td_bank_credits SET claimed_by_order = $1 WHERE utr = $2', [orderId, utr.trim()]);
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('UPDATE bank_credits SET claimed_by_order = ? WHERE utr = ?').run(orderId, utr.trim());
    } catch(e) {}
  }
}

async function verifyUtr(utr, orderId) {
  if (!utr || typeof utr !== 'string') {
    return { valid: false, error: '12-digit Bank UTR / Reference number is required.' };
  }
  const cleanUtr = utr.trim();
  if (!/^\d{12}$/.test(cleanUtr)) {
    return { valid: false, error: 'Invalid UTR format. NPCI / Bank UTR must be exactly 12 digits (numeric).' };
  }

  // Anti-Replay Security Check
  if (pgPool) {
    try {
      const res = await pgPool.query(
        "SELECT id, status, payment FROM td_orders WHERE (payment->>'utr' = $1 OR payment->>'codUtr' = $1 OR payment->>'transactionHash' LIKE $2)",
        [cleanUtr, `%${cleanUtr}%`]
      );
      if (res.rows && res.rows.length > 0) {
        const conflict = res.rows.find(r => !orderId || r.id.toUpperCase() !== orderId.toUpperCase());
        if (conflict) {
          return { valid: false, error: `Anti-Replay Alert: This UTR (${cleanUtr}) has already been registered with order ${conflict.id}. Duplicate payment references are strictly rejected.` };
        }
      }
    } catch(e) {
      console.warn('[DB] verifyUtr PG check error:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      const rows = sqliteDb.prepare('SELECT id, payment FROM orders').all();
      for (const row of rows) {
        if (!orderId || row.id.toUpperCase() !== orderId.toUpperCase()) {
          try {
            const p = typeof row.payment === 'string' ? JSON.parse(row.payment || '{}') : (row.payment || {});
            if (p.utr === cleanUtr || p.codUtr === cleanUtr || (p.transactionHash && p.transactionHash.includes(cleanUtr))) {
              return { valid: false, error: `Anti-Replay Alert: This UTR (${cleanUtr}) has already been registered with order ${row.id}. Duplicate payment references are strictly rejected.` };
            }
          } catch(e) {}
        }
      }
    } catch(e) {}
  }

  // Check if real bank credit notification has confirmed this UTR
  const bankMatch = await checkBankCredit({ utr: cleanUtr });
  const isAutoVerified = bankMatch && bankMatch.found;

  return { 
    valid: true, 
    utr: cleanUtr, 
    autoVerified: isAutoVerified,
    pendingReview: !isAutoVerified 
  };
}

async function confirmOrderUtr(utr, orderId) {
  const verification = await verifyUtr(utr, orderId);
  if (!verification.valid) return verification;

  const newStatus = verification.autoVerified 
    ? `Paid & Verified via UPI (Ref: ${verification.utr})`
    : `Payment Submitted (Pending Concierge Bank Verification · Ref: ${verification.utr})`;

  if (verification.autoVerified && orderId) {
    await claimBankCredit(verification.utr, orderId);
  }

  if (pgPool && orderId) {
    try {
      await pgPool.query(
        `UPDATE td_orders SET status = $1, payment = jsonb_set(COALESCE(payment, '{}'::jsonb), '{utr}', $2) WHERE UPPER(id) = UPPER($3)`,
        [newStatus, JSON.stringify(verification.utr), orderId]
      );
    } catch(e) {}
  }
  if (sqliteDb && orderId) {
    try {
      const row = sqliteDb.prepare('SELECT payment FROM orders WHERE UPPER(id) = ?').get(orderId.toUpperCase());
      if (row) {
        let p = {};
        try { p = JSON.parse(row.payment || '{}'); } catch(e) {}
        p.utr = verification.utr;
        sqliteDb.prepare('UPDATE orders SET status = ?, payment = ? WHERE UPPER(id) = ?').run(newStatus, JSON.stringify(p), orderId.toUpperCase());
      }
    } catch(e) {}
  }
  return { valid: true, utr: verification.utr, status: newStatus, autoVerified: verification.autoVerified };
}

async function saveSettings(settingsObj) {
  if (pgPool) {
    try {
      for (const [k, v] of Object.entries(settingsObj)) {
        await pgPool.query(
          'INSERT INTO td_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2',
          [k, JSON.stringify(v)]
        );
      }
    } catch(e) {
      console.error('[DB] saveSettings PG error:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      const stmt = sqliteDb.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
      Object.entries(settingsObj).forEach(([k, v]) => {
        stmt.run(k, JSON.stringify(v));
      });
    } catch(e) {}
  }

  return { success: true, settings: settingsObj };
}

// -------------------------------------------------------------------------
// CATEGORIES API
// -------------------------------------------------------------------------
async function getCategories() {
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT name FROM td_categories ORDER BY name ASC');
      return res.rows.map(r => r.name);
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT name FROM categories').all().map(c => c.name);
    } catch(e) {}
  }
  try {
    const raw = JSON.parse(fs.readFileSync(JSON_DB_PATH, 'utf8'));
    return raw.categories || [];
  } catch(e) {
    return [];
  }
}

async function addCategories(cats) {
  const list = Array.isArray(cats) ? cats : [cats];
  if (pgPool) {
    try {
      for (const c of list) {
        if (c && typeof c === 'string' && c.trim()) {
          await pgPool.query('INSERT INTO td_categories (name) VALUES ($1) ON CONFLICT (name) DO NOTHING', [c.trim()]);
        }
      }
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      const insert = sqliteDb.prepare('INSERT OR IGNORE INTO categories (name) VALUES (?)');
      list.forEach(c => {
        if (c && typeof c === 'string' && c.trim()) insert.run(c.trim());
      });
    } catch(e) {}
  }
  return await getCategories();
}

async function deleteCategory(name) {
  if (pgPool) {
    try {
      await pgPool.query('DELETE FROM td_categories WHERE LOWER(name) = LOWER($1)', [name.trim()]);
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('DELETE FROM categories WHERE LOWER(name) = LOWER(?)').run(name.trim());
    } catch(e) {}
  }
  return await getCategories();
}

// -------------------------------------------------------------------------
// REVIEWS API
// -------------------------------------------------------------------------
async function getReviews(productId) {
  if (pgPool) {
    try {
      let res;
      if (productId) {
        res = await pgPool.query('SELECT * FROM td_reviews WHERE "productId" = $1 ORDER BY date DESC', [productId]);
      } else {
        res = await pgPool.query('SELECT * FROM td_reviews ORDER BY date DESC');
      }
      return res.rows.map(r => ({
        id: r.id,
        productId: r.productId,
        customerName: r.customerName,
        rating: Number(r.rating),
        fitFeedback: r.fitFeedback,
        reviewTitle: r.reviewTitle,
        comment: r.comment,
        verifiedPurchase: Boolean(r.verifiedPurchase),
        date: r.date
      }));
    } catch(e) {}
  }

  if (sqliteDb) {
    try {
      if (productId) {
        return sqliteDb.prepare('SELECT * FROM reviews WHERE productId = ? ORDER BY rowid DESC').all(productId);
      }
      return sqliteDb.prepare('SELECT * FROM reviews ORDER BY rowid DESC').all();
    } catch(e) {}
  }

  return [];
}

async function saveReview(rev) {
  const revId = rev.id || ('REV-' + Date.now().toString().slice(-6));
  const dateStr = rev.date || new Date().toISOString();

  if (pgPool) {
    try {
      await pgPool.query(`
        INSERT INTO td_reviews (id, "productId", "customerName", rating, "fitFeedback", "reviewTitle", comment, "verifiedPurchase", date)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (id) DO UPDATE SET
          rating = EXCLUDED.rating,
          comment = EXCLUDED.comment
      `, [
        revId, rev.productId, rev.customerName || 'Verified Client',
        Number(rev.rating) || 5, rev.fitFeedback || 'True to size',
        rev.reviewTitle || 'Exceptional craftsmanship', rev.comment || '',
        true, dateStr
      ]);
      return { success: true, id: revId };
    } catch(e) {
      console.error('[DB] saveReview PG error:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      sqliteDb.prepare(`
        INSERT INTO reviews (id, productId, customerName, rating, fitFeedback, reviewTitle, comment, verifiedPurchase, date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        revId, rev.productId, rev.customerName || 'Verified Client',
        Number(rev.rating) || 5, rev.fitFeedback || 'True to size',
        rev.reviewTitle || 'Exceptional craftsmanship', rev.comment || '',
        1, dateStr
      );
      return { success: true, id: revId };
    } catch(e) {}
  }

  return { success: true, id: revId };
}

// -------------------------------------------------------------------------
// SUBSCRIBERS API
// -------------------------------------------------------------------------
async function getSubscribers() {
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM td_subscribers ORDER BY date DESC');
      return res.rows;
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT * FROM subscribers ORDER BY rowid DESC').all();
    } catch(e) {}
  }
  return [];
}

async function addSubscriber(email) {
  const cleanEmail = (email || '').trim().toLowerCase();
  const dateStr = new Date().toISOString();
  if (pgPool) {
    try {
      await pgPool.query('INSERT INTO td_subscribers (email, date) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING', [cleanEmail, dateStr]);
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('INSERT OR IGNORE INTO subscribers (email, date) VALUES (?, ?)').run(cleanEmail, dateStr);
    } catch(e) {}
  }
  return { success: true, promoCode: 'TOKYO10' };
}

// -------------------------------------------------------------------------
// RESTOCK ALERTS API
// -------------------------------------------------------------------------
async function getRestockAlerts() {
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM td_restock_alerts ORDER BY date DESC');
      return res.rows;
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT * FROM restock_alerts ORDER BY rowid DESC').all();
    } catch(e) {}
  }
  return [];
}

async function saveRestockAlert({ productId, size, email }) {
  const id = 'ALT-' + Date.now().toString().slice(-6);
  const dateStr = new Date().toISOString();
  if (pgPool) {
    try {
      await pgPool.query(
        'INSERT INTO td_restock_alerts (id, "productId", size, email, date) VALUES ($1, $2, $3, $4, $5)',
        [id, productId, size || 'ANY', (email || '').toLowerCase(), dateStr]
      );
      return { success: true, id };
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('INSERT INTO restock_alerts (id, productId, size, email, date) VALUES (?, ?, ?, ?, ?)').run(
        id, productId, size || 'ANY', (email || '').toLowerCase(), dateStr
      );
      return { success: true, id };
    } catch(e) {}
  }
  return { success: true, id };
}

async function deleteRestockAlert(id) {
  if (pgPool) {
    try {
      await pgPool.query('DELETE FROM td_restock_alerts WHERE id = $1', [id]);
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('DELETE FROM restock_alerts WHERE id = ?').run(id);
    } catch(e) {}
  }
  return { success: true, id };
}

// -------------------------------------------------------------------------
// APPOINTMENTS API
// -------------------------------------------------------------------------
async function getAppointments() {
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM td_appointments ORDER BY created_at DESC');
      return res.rows.map(a => ({
        id: a.id,
        clientName: a.clientName,
        email: a.email,
        phone: a.phone,
        city: a.city,
        preferredDate: a.preferredDate,
        stylingInterests: a.stylingInterests,
        status: a.status,
        created_at: a.created_at
      }));
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT * FROM appointments ORDER BY rowid DESC').all();
    } catch(e) {}
  }
  return [];
}

async function saveAppointment(apt) {
  const id = apt.id || ('APT-' + Math.floor(1000 + Math.random() * 9000));
  const created = apt.created_at || new Date().toISOString();

  if (pgPool) {
    try {
      await pgPool.query(`
        INSERT INTO td_appointments (id, "clientName", email, phone, city, "preferredDate", "stylingInterests", status, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status
      `, [
        id, apt.clientName || 'Private Client', (apt.email || '').toLowerCase(),
        apt.phone || '', apt.city || 'Tokyo Atelier',
        apt.preferredDate || 'Upcoming Drop Date', apt.stylingInterests || 'Atelier Collection',
        apt.status || 'Confirmed', created
      ]);
      return { success: true, id };
    } catch(e) {}
  }

  if (sqliteDb) {
    try {
      sqliteDb.prepare(`
        INSERT INTO appointments (id, clientName, email, phone, city, preferredDate, stylingInterests, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, apt.clientName || 'Private Client', (apt.email || '').toLowerCase(),
        apt.phone || '', apt.city || 'Tokyo Atelier',
        apt.preferredDate || 'Upcoming Drop Date', apt.stylingInterests || 'Atelier Collection',
        apt.status || 'Confirmed', created
      );
      return { success: true, id };
    } catch(e) {}
  }

  return { success: true, id };
}

async function updateAppointment(id, status) {
  if (pgPool) {
    try {
      await pgPool.query('UPDATE td_appointments SET status = $1 WHERE id = $2', [status, id]);
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('UPDATE appointments SET status = ? WHERE id = ?').run(status, id);
    } catch(e) {}
  }
  return { success: true, id, status };
}

async function deleteAppointment(id) {
  if (pgPool) {
    try {
      await pgPool.query('DELETE FROM td_appointments WHERE id = $1', [id]);
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('DELETE FROM appointments WHERE id = ?').run(id);
    } catch(e) {}
  }
  return { success: true, id };
}

// -------------------------------------------------------------------------
// CUSTOMERS & SESSIONS API
// -------------------------------------------------------------------------
async function getCustomerByEmail(email) {
  const cleanEmail = (email || '').trim().toLowerCase();
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM td_customers WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
      if (res.rows[0]) return res.rows[0];
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT * FROM customers WHERE LOWER(email) = LOWER(?)').get(cleanEmail);
    } catch(e) {}
  }
  return null;
}

async function getCustomerById(id) {
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM td_customers WHERE id = $1', [id]);
      if (res.rows[0]) return res.rows[0];
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT * FROM customers WHERE id = ?').get(id);
    } catch(e) {}
  }
  return null;
}

async function saveCustomer(c) {
  if (pgPool) {
    try {
      await pgPool.query(`
        INSERT INTO td_customers (id, name, email, "passwordHash", phone, address, city, "postalCode", country, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (email) DO UPDATE SET
          name = EXCLUDED.name,
          phone = EXCLUDED.phone,
          address = EXCLUDED.address,
          city = EXCLUDED.city,
          "postalCode" = EXCLUDED."postalCode",
          country = EXCLUDED.country
      `, [
        c.id, c.name, c.email.toLowerCase(), c.passwordHash,
        c.phone || '', c.address || '', c.city || '',
        c.postalCode || '', c.country || 'Japan', c.created_at || new Date().toISOString()
      ]);
      return { success: true, customer: c };
    } catch(e) {
      console.error('[DB] saveCustomer PG error:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      sqliteDb.prepare(`
        INSERT INTO customers (id, name, email, passwordHash, phone, address, city, postalCode, country, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        c.id, c.name, c.email.toLowerCase(), c.passwordHash,
        c.phone || '', c.address || '', c.city || '',
        c.postalCode || '', c.country || 'Japan', c.created_at || new Date().toISOString()
      );
      return { success: true, customer: c };
    } catch(e) {}
  }

  return { success: true, customer: c };
}

async function updateCustomerProfile(id, updates) {
  if (pgPool) {
    try {
      await pgPool.query(`
        UPDATE td_customers
        SET name = COALESCE($1, name),
            phone = COALESCE($2, phone),
            address = COALESCE($3, address),
            city = COALESCE($4, city),
            "postalCode" = COALESCE($5, "postalCode"),
            country = COALESCE($6, country)
        WHERE id = $7
      `, [updates.name, updates.phone, updates.address, updates.city, updates.postalCode, updates.country, id]);
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare(`
        UPDATE customers 
        SET name = COALESCE(?, name),
            phone = COALESCE(?, phone),
            address = COALESCE(?, address),
            city = COALESCE(?, city),
            postalCode = COALESCE(?, postalCode),
            country = COALESCE(?, country)
        WHERE id = ?
      `).run(updates.name, updates.phone, updates.address, updates.city, updates.postalCode, updates.country, id);
    } catch(e) {}
  }
  return await getCustomerById(id);
}

async function saveSession(token, customerId, expiresAt) {
  const created = new Date().toISOString();
  if (pgPool) {
    try {
      await pgPool.query(`
        INSERT INTO td_customer_sessions (token, "customerId", created_at, expires_at)
        VALUES ($1, $2, $3, $4)
      `, [token, customerId, created, expiresAt]);
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('INSERT INTO customer_sessions (token, customerId, created_at, expires_at) VALUES (?, ?, ?, ?)').run(
        token, customerId, created, expiresAt
      );
    } catch(e) {}
  }
}

async function getSessionCustomer(token) {
  if (!token) return null;
  if (pgPool) {
    try {
      const res = await pgPool.query(`
        SELECT c.id, c.name, c.email, c.phone, c.address, c.city, c."postalCode", c.country, c.created_at
        FROM td_customer_sessions s
        JOIN td_customers c ON s."customerId" = c.id
        WHERE s.token = $1 AND (s.expires_at IS NULL OR s.expires_at::timestamptz > NOW())
      `, [token]);
      if (res.rows[0]) return res.rows[0];
    } catch(e) {
      console.error('[DB] getSessionCustomer PG error:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      const nowIso = new Date().toISOString();
      const session = sqliteDb.prepare('SELECT customerId FROM customer_sessions WHERE token = ? AND (expires_at IS NULL OR expires_at > ?)').get(token, nowIso);
      if (session) {
        return sqliteDb.prepare('SELECT id, name, email, phone, address, city, postalCode, country, created_at FROM customers WHERE id = ?').get(session.customerId);
      }
    } catch(e) {}
  }

  return null;
}

async function deleteSession(token) {
  if (pgPool) {
    try {
      await pgPool.query('DELETE FROM td_customer_sessions WHERE token = $1', [token]);
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('DELETE FROM customer_sessions WHERE token = ?').run(token);
    } catch(e) {}
  }
  return { success: true };
}

async function getAllCustomers() {
  let list = [];
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT id, name, email, phone, address, city, "postalCode", country, created_at FROM td_customers ORDER BY created_at DESC');
      list = res.rows;
    } catch(e) {}
  } else if (sqliteDb) {
    try {
      list = sqliteDb.prepare('SELECT id, name, email, phone, address, city, postalCode, country, created_at FROM customers ORDER BY rowid DESC').all();
    } catch(e) {}
  }

  const allOrders = await getOrders();
  return list.map(c => {
    const cOrders = allOrders.filter(o => {
      try {
        const cust = o.customer || {};
        return (cust.email && cust.email.toLowerCase() === (c.email || '').toLowerCase()) || o.customerId === c.id;
      } catch(e) { return false; }
    });
    const totalSpent = cOrders.reduce((sum, o) => {
      try {
        const fin = o.financials || {};
        return sum + (Number(fin.grandTotal) || 0);
      } catch(e) { return sum; }
    }, 0);
    return {
      ...c,
      orderCount: cOrders.length,
      totalSpent
    };
  });
}

// -------------------------------------------------------------------------
// VISITOR ANALYTICS & TELEMETRY
// -------------------------------------------------------------------------
// In-memory telemetry cache to prevent expensive full-table scans on every click
let totalViewsCountCache = null;
let cachedViewsSummary = null;
let cachedViewsSummaryTs = 0;

async function trackView({ path, referrer, device, ip }) {
  if (pgPool) {
    try {
      await pgPool.query(
        'INSERT INTO td_page_views (path, referrer, device, ip) VALUES ($1, $2, $3, $4)',
        [path || '/', referrer || 'Direct', device || 'Desktop', ip || '127.0.0.1']
      );
      if (totalViewsCountCache === null) {
        const total = await pgPool.query('SELECT count(*) FROM td_page_views');
        totalViewsCountCache = parseInt(total.rows[0].count, 10);
      } else {
        totalViewsCountCache += 1;
      }
      return { success: true, totalViews: totalViewsCountCache };
    } catch(e) {
      console.warn('[DB] trackView PG notice:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      const viewId = 'VW-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
      sqliteDb.prepare(`
        INSERT INTO page_views (id, path, referrer, device, ip, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(viewId, path || '/', referrer || 'Direct', device || 'Desktop', ip || '127.0.0.1', new Date().toISOString());
      if (totalViewsCountCache === null) {
        const countRow = sqliteDb.prepare('SELECT COUNT(*) as count FROM page_views').get();
        totalViewsCountCache = countRow ? countRow.count : 1;
      } else {
        totalViewsCountCache += 1;
      }
      return { success: true, totalViews: totalViewsCountCache };
    } catch(e) {}
  }

  return { success: true, totalViews: totalViewsCountCache || 1 };
}

async function getViews() {
  const now = Date.now();
  if (cachedViewsSummary && (now - cachedViewsSummaryTs < 30000)) {
    return cachedViewsSummary;
  }

  if (pgPool) {
    try {
      const totalRes = await pgPool.query('SELECT count(*) FROM td_page_views');
      const todayRes = await pgPool.query("SELECT count(*) FROM td_page_views WHERE created_at >= CURRENT_DATE");
      const uniqueRes = await pgPool.query('SELECT count(DISTINCT ip) FROM td_page_views');
      const topRes = await pgPool.query('SELECT path, count(*) as count FROM td_page_views GROUP BY path ORDER BY count DESC LIMIT 10');
      const recentRes = await pgPool.query('SELECT id, path, referrer, device, created_at FROM td_page_views ORDER BY id DESC LIMIT 50');

      const byPage = {};
      topRes.rows.forEach(r => { byPage[r.path || '/'] = parseInt(r.count, 10); });

      cachedViewsSummary = {
        totalViews: parseInt(totalRes.rows[0].count, 10),
        todayViews: parseInt(todayRes.rows[0].count, 10),
        uniqueVisitors: parseInt(uniqueRes.rows[0].count, 10),
        byPage,
        recent: recentRes.rows
      };
      cachedViewsSummaryTs = now;
      totalViewsCountCache = cachedViewsSummary.totalViews;
      return cachedViewsSummary;
    } catch(e) {
      console.error('[DB] getViews PG error:', e.message);
    }
  }

  if (sqliteDb) {
    try {
      const totalRow = sqliteDb.prepare('SELECT COUNT(*) as count FROM page_views').get();
      const todayStr = new Date().toISOString().slice(0, 10);
      const todayRow = sqliteDb.prepare('SELECT COUNT(*) as count FROM page_views WHERE created_at LIKE ?').get(`${todayStr}%`);
      const uniqueRow = sqliteDb.prepare('SELECT COUNT(DISTINCT ip) as count FROM page_views').get();
      const topPages = sqliteDb.prepare('SELECT path, COUNT(*) as count FROM page_views GROUP BY path ORDER BY count DESC LIMIT 10').all();
      const recent = sqliteDb.prepare('SELECT id, path, referrer, device, created_at FROM page_views ORDER BY rowid DESC LIMIT 50').all();

      const byPage = {};
      topPages.forEach(p => { byPage[p.path || '/'] = p.count; });

      cachedViewsSummary = {
        totalViews: totalRow ? totalRow.count : 0,
        todayViews: todayRow ? todayRow.count : 0,
        uniqueVisitors: uniqueRow ? uniqueRow.count : 0,
        byPage,
        recent
      };
      cachedViewsSummaryTs = now;
      totalViewsCountCache = cachedViewsSummary.totalViews;
      return cachedViewsSummary;
    } catch(e) {}
  }

  return { totalViews: 0, todayViews: 0, uniqueVisitors: 0, byPage: {}, recent: [] };
}

async function clearViews() {
  if (pgPool) {
    try {
      await pgPool.query('TRUNCATE TABLE td_page_views RESTART IDENTITY');
    } catch(e) {}
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('DELETE FROM page_views').run();
    } catch(e) {}
  }
  return { success: true };
}

// -------------------------------------------------------------------------
// CLOUD UPLOADS STORAGE (PERSISTS IMAGES PERMANENTLY IN POSTGRESQL)
// -------------------------------------------------------------------------
async function saveUpload(filename, mime, base64Data) {
  if (pgPool) {
    try {
      await pgPool.query(`
        INSERT INTO td_uploads (id, filename, mime, data, created_at)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, mime = EXCLUDED.mime
      `, [filename, filename, mime, base64Data]);
      return { success: true, filename };
    } catch(e) {
      console.error('[DB] saveUpload PG error:', e.message);
    }
  }
  return { success: true, filename };
}

async function getUpload(filename) {
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT mime, data FROM td_uploads WHERE id = $1 OR filename = $1', [filename]);
      if (res.rows[0]) {
        return res.rows[0];
      }
    } catch(e) {
      console.error('[DB] getUpload PG error:', e.message);
    }
  }
  return null;
}

// -------------------------------------------------------------------------
// FULL BACKUP / EXPORT & IMPORT
// -------------------------------------------------------------------------
async function ping() {
  if (pgPool) {
    try {
      await pgPool.query('SELECT 1');
      return { ok: true, engine: 'postgresql' };
    } catch(e) {
      return { ok: false, engine: 'postgresql', error: e.message };
    }
  }
  if (sqliteDb) {
    try {
      sqliteDb.prepare('SELECT 1').get();
      return { ok: true, engine: 'sqlite' };
    } catch(e) {
      return { ok: false, engine: 'sqlite', error: e.message };
    }
  }
  return { ok: true, engine: 'json_file' };
}

async function getFullDatabase({ isAdmin = false } = {}) {
  // If not admin, only fetch public catalog to eliminate 10-second serverless timeouts and data exposure
  if (!isAdmin) {
    const [products, settings, categories, promos, reviews] = await Promise.all([
      getProducts(),
      getSettings(),
      getCategories(),
      (async () => {
        if (pgPool) {
          try {
            const r = await pgPool.query('SELECT * FROM td_promos');
            return r.rows;
          } catch(e) { return []; }
        }
        if (sqliteDb) {
          try { return sqliteDb.prepare('SELECT * FROM promos').all(); } catch(e) { return []; }
        }
        return [];
      })(),
      getReviews()
    ]);

    const safeSettings = { ...settings };
    delete safeSettings.adminPassword;

    return {
      type: pgPool ? 'postgresql' : (sqliteDb ? 'sqlite' : 'json_file'),
      databaseEngine: pgPool ? 'PostgreSQL (Cloud Supabase)' : 'SQLite Native Sync',
      products,
      orders: [],
      settings: safeSettings,
      categories,
      promos,
      reviews,
      subscribers: [],
      restockAlerts: [],
      appointments: [],
      customers: [],
      views: {
        totalViews: totalViewsCountCache || 1,
        todayViews: 1,
        uniqueVisitors: 1,
        byPage: {},
        recent: []
      }
    };
  }

  // Full administrative database extraction in small parallel batches to balance connection pool and network roundtrips
  const [products, orders, settings, categories] = await Promise.all([
    getProducts(),
    getOrders(),
    getSettings(),
    getCategories()
  ]);
  const [reviews, subscribers, alerts, appointments] = await Promise.all([
    getReviews(),
    getSubscribers(),
    getRestockAlerts(),
    getAppointments()
  ]);
  const [customers, views] = await Promise.all([
    getAllCustomers(),
    getViews()
  ]);

  let promos = [];
  if (pgPool) {
    try {
      const r = await pgPool.query('SELECT * FROM td_promos');
      promos = r.rows;
    } catch(e) {}
  } else if (sqliteDb) {
    try {
      promos = sqliteDb.prepare('SELECT * FROM promos').all();
    } catch(e) {}
  }

  return {
    type: pgPool ? 'postgresql' : (sqliteDb ? 'sqlite' : 'json_file'),
    databaseEngine: pgPool ? 'PostgreSQL (Cloud Supabase)' : 'SQLite Native Sync',
    products,
    orders,
    settings,
    categories,
    promos,
    reviews,
    subscribers,
    restockAlerts: alerts,
    appointments,
    customers,
    views
  };
}

async function importDatabase(imported) {
  if (!imported) return { success: false };
  if (Array.isArray(imported.products)) {
    for (const p of imported.products) {
      await saveProduct(p);
    }
  }
  if (imported.settings && typeof imported.settings === 'object') {
    await saveSettings(imported.settings);
  }
  if (Array.isArray(imported.categories)) {
    await addCategories(imported.categories);
  }
  return { success: true };
}

module.exports = {
  init,
  getProducts,
  saveProduct,
  deleteProduct,
  getOrders,
  saveOrder,
  updateOrder,
  deleteOrder,
  getTracking,
  getSettings,
  saveSettings,
  getCategories,
  addCategories,
  deleteCategory,
  getReviews,
  saveReview,
  getSubscribers,
  addSubscriber,
  getRestockAlerts,
  saveRestockAlert,
  deleteRestockAlert,
  getAppointments,
  saveAppointment,
  updateAppointment,
  deleteAppointment,
  getCustomerByEmail,
  getCustomerById,
  saveCustomer,
  updateCustomerProfile,
  saveSession,
  getSessionCustomer,
  deleteSession,
  getAllCustomers,
  trackView,
  getViews,
  clearViews,
  saveUpload,
  getUpload,
  getFullDatabase,
  importDatabase,
  verifyUtr,
  confirmOrderUtr,
  recordBankCredit,
  checkBankCredit,
  claimBankCredit,
  ping
};
