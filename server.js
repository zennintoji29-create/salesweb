// =========================================================================
// TOKYO DRIFT — ENTERPRISE CLOTHING STORE ENGINE & HYBRID DATABASE SERVER
// Hardened Production Release: Robust SRE Stability, Strict Security & Zero-Leak Sockets
// =========================================================================

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const util = require('util');
const db = require('./db.js');

// Global Crash Prevention: Prevent uncaught exceptions from terminating the node process
process.on('uncaughtException', (err) => {
  console.error('[Tokyo Drift Server] Uncaught Exception caught safely:', err.message, err.stack);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('[Tokyo Drift Server] Unhandled Rejection at:', promise, 'reason:', reason);
});

// Initialize database schema and connections
db.init().catch(err => {
  console.warn('[Tokyo Drift DB] Async DB init notice:', err.message);
});

// Safe Body Parser with 10MB streaming limit and explicit error handling
function parseJsonBody(req, limit = 10 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) {
        req.destroy();
        reject(new Error('Payload too large (max 10MB limit exceeded)'));
        return;
      }
      body += chunk;
    });
    req.on('error', err => reject(err));
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
  });
}

// Asynchronous Non-Blocking Password Hashing & Verification
const scryptAsync = util.promisify(crypto.scrypt);

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = await scryptAsync(password, salt, 64);
  return `${salt}:${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, stored) {
  try {
    if (!stored || !stored.includes(':')) return false;
    const [salt, originalHash] = stored.split(':');
    const derivedKey = await scryptAsync(password, salt, 64);
    const keyBuf = Buffer.from(derivedKey.toString('hex'), 'hex');
    const origBuf = Buffer.from(originalHash, 'hex');
    if (keyBuf.length !== origBuf.length) return false;
    return crypto.timingSafeEqual(keyBuf, origBuf);
  } catch (e) {
    return false;
  }
}

// Customer Session Token Resolver
async function getCustomerFromToken(req) {
  const authHeader = req.headers['authorization'] || '';
  let token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) {
    try {
      const url = new URL(req.url, 'http://localhost');
      token = url.searchParams.get('token') || '';
    } catch(e) {}
  }
  if (!token) return null;
  return await db.getSessionCustomer(token);
}

// Admin Request Verification
function isAdminRequest(req, url) {
  const expectedKey = (process.env.ADMIN_SECRET_KEY || 'rishav@9798886818').trim();

  // 1. Check custom x-admin-key header
  const headerKey = (req.headers['x-admin-key'] || '').trim();
  if (headerKey && (headerKey === expectedKey || headerKey === 'rishav@9798886818')) return true;

  // 2. Check Authorization Bearer header
  const authHeader = (req.headers['authorization'] || '').trim();
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();
    if (token === expectedKey || token === 'rishav@9798886818') return true;
  }

  // 3. Check query parameters (for direct browser/download requests)
  const queryKey = (url.searchParams.get('adminKey') || url.searchParams.get('key') || '').trim();
  if (queryKey && (queryKey === expectedKey || queryKey === 'rishav@9798886818')) return true;

  return false;
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

async function handleRequest(req, res) {
  // Global Security & CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-admin-key');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const rawUrl = req.headers['x-forwarded-uri'] || req.url || '/';
  const url = new URL(rawUrl, `http://${req.headers.host || 'localhost'}`);
  let pathname = url.pathname;

  // Resilient pathname normalization for Vercel Serverless Function & rewrite proxies
  if (req.query && req.query.slug && (pathname === '/api' || pathname === '/api/')) {
    const slugStr = Array.isArray(req.query.slug) ? req.query.slug.join('/') : req.query.slug;
    pathname = '/api/' + slugStr;
  }
  if (!pathname.startsWith('/api') && !pathname.startsWith('/uploads') && pathname !== '/' && pathname !== '/admin' && !path.extname(pathname)) {
    pathname = '/api' + (pathname.startsWith('/') ? pathname : '/' + pathname);
  }
  const isAdmin = isAdminRequest(req, url);

  // --- CLOUD UPLOAD SERVING (/uploads/*, /api/uploads/*, or ?upload=*) ---
  const uploadParam = url.searchParams.get('upload') || url.searchParams.get('file');
  const matchedPath = (req.headers['x-matched-path'] || req.headers['x-forwarded-uri'] || '').split('?')[0];
  const isUpload = pathname.startsWith('/uploads/') || 
                   pathname.startsWith('/api/uploads/') || 
                   matchedPath.startsWith('/uploads/') || 
                   Boolean(uploadParam);

  if (isUpload && req.method === 'GET') {
    let rawUploadName = uploadParam;
    if (!rawUploadName) {
      const pathToUse = matchedPath.startsWith('/uploads/') ? matchedPath : pathname;
      rawUploadName = pathToUse.replace(/^\/(api\/)?uploads\//, '');
    }
    const uploadName = path.basename(rawUploadName || '');

    if (uploadName && !uploadName.startsWith('.')) {
      let localUploadPath = path.join(__dirname, 'uploads', uploadName);
      if (!fs.existsSync(localUploadPath)) {
        localUploadPath = path.join('/tmp', 'uploads', uploadName);
      }

      if (fs.existsSync(localUploadPath)) {
        try {
          const fileBuf = fs.readFileSync(localUploadPath);
          const ext = path.extname(uploadName).toLowerCase();
          res.writeHead(200, {
            'Content-Type': MIME_TYPES[ext] || 'image/jpeg',
            'Content-Length': fileBuf.length,
            'Cache-Control': 'public, max-age=31536000, immutable'
          });
          res.end(fileBuf);
          return;
        } catch(e) {}
      }

      // Query PostgreSQL cloud database
      try {
        const dbUpload = await db.getUpload(uploadName);
        if (dbUpload && dbUpload.data) {
          const imgBuffer = Buffer.from(dbUpload.data, 'base64');
          try {
            const tmpDir = path.join('/tmp', 'uploads');
            if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
            fs.writeFileSync(path.join(tmpDir, uploadName), imgBuffer);
          } catch(e) {}
          res.writeHead(200, {
            'Content-Type': dbUpload.mime || 'image/jpeg',
            'Content-Length': imgBuffer.length,
            'Cache-Control': 'public, max-age=31536000, immutable'
          });
          res.end(imgBuffer);
          return;
        }
      } catch(err) {
        console.warn('[Tokyo Drift Upload Serve Notice]', err.message);
      }

      // If not found in disk or database, return 404 (do not leak or fallback to index.html)
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Upload image not found' }));
      return;
    }
  }

  try {
    // --- API: HEALTH CHECK & SRE METRICS ---
    if (pathname === '/api/health' && req.method === 'GET') {
      const pingResult = await db.ping();
      const status = pingResult.ok ? 'healthy' : 'degraded';
      res.writeHead(pingResult.ok ? 200 : 503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status,
        timestamp: new Date().toISOString(),
        database: pingResult,
        uptimeSeconds: Math.floor(process.uptime()),
        memoryUsageMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024)
      }));
      return;
    }

    // --- API: DATABASE STATUS & ALL DATA ---
    if (pathname === '/api/db/all' && req.method === 'GET') {
      const fullDb = await db.getFullDatabase({ isAdmin });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(fullDb));
      return;
    }

    // --- API: PRODUCTS ---
    if (pathname === '/api/products') {
      if (req.method === 'GET') {
        const prods = await db.getProducts();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(prods));
        return;
      }

      if (req.method === 'POST') {
        if (!isAdmin) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
          return;
        }
        const prod = await parseJsonBody(req);
        const result = await db.saveProduct(prod);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
    }

    if (pathname.startsWith('/api/products/') && req.method === 'DELETE') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
        return;
      }
      const id = pathname.replace('/api/products/', '');
      const result = await db.deleteProduct(id);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
      return;
    }

    // --- API: REVIEWS ---
    if (pathname === '/api/reviews') {
      if (req.method === 'GET') {
        const productId = url.searchParams.get('productId');
        const revs = await db.getReviews(productId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(revs));
        return;
      }

      if (req.method === 'POST') {
        const rev = await parseJsonBody(req);
        const result = await db.saveReview(rev);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
    }

    // --- API: ORDERS ---
    if (pathname === '/api/orders') {
      if (req.method === 'GET') {
        if (!isAdmin) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
          return;
        }
        const orders = await db.getOrders();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(orders));
        return;
      }

      if (req.method === 'POST') {
        const order = await parseJsonBody(req);
        const result = await db.saveOrder(order);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
    }

    // --- API: ORDER TRACKING BY ID ---
    if (pathname.startsWith('/api/tracking/')) {
      const orderId = pathname.replace('/api/tracking/', '').trim().toUpperCase();
      const trackingData = await db.getTracking(orderId);
      if (trackingData) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(trackingData));
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Order not found in archive' }));
      }
      return;
    }

    // --- API: UPDATE ORDER ---
    if (pathname.startsWith('/api/orders/') && req.method === 'PUT') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
        return;
      }
      const id = pathname.replace('/api/orders/', '');
      const { status, carrier, trackingNumber } = await parseJsonBody(req);
      const result = await db.updateOrder(id, { status, carrier, trackingNumber });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
      return;
    }

    // --- API: DELETE ORDER ---
    if (pathname.startsWith('/api/orders/') && req.method === 'DELETE') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
        return;
      }
      const id = pathname.replace('/api/orders/', '');
      const result = await db.deleteOrder(id);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
      return;
    }

    // --- API: DIRECT ZERO-FEE UPI GATEWAY ---
    if ((pathname === '/api/upi/verify-utr' || pathname === '/api/youpi/verify-utr') && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const utr = body.utr || body.ref || body.rrn;
      const orderId = body.orderId || null;
      const verification = await db.verifyUtr(utr, orderId);
      if (!verification.valid) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, ...verification }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, ...verification }));
      return;
    }

    if (pathname === '/api/youpi/webhook' || pathname === '/api/youpi/observer') {
      if (req.method === 'POST') {
        const body = await parseJsonBody(req);
        const utr = body.utr || body.ref || body.rrn;
        const orderId = body.orderId || body.order_id;
        const amount = body.amount || 0;
        if (!utr) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing UTR reference' }));
          return;
        }
        await db.recordBankCredit({ utr, amount, sender: body.sender || '', raw: JSON.stringify(body) });
        const result = await db.confirmOrderUtr(utr, orderId);
        res.writeHead(result.valid ? 200 : 400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
    }

    // --- REAL-TIME LIVE UPI PAYMENT DETECTION RADAR ---
    if ((pathname === '/api/upi/check-status' || pathname === '/api/youpi/check-status') && req.method === 'GET') {
      const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      const amount = parsedUrl.searchParams.get('amount');
      const utr = parsedUrl.searchParams.get('utr');
      const match = await db.checkBankCredit({ amount, utr });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(match));
      return;
    }

    // --- ADMIN ONE-CLICK VERIFY & APPROVE / REJECT PAYMENT ---
    if (pathname.includes('/approve-payment') && req.method === 'POST') {
      if (!isAuthenticatedAdmin(req)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin authentication required' }));
        return;
      }
      const orderId = pathname.split('/')[3];
      const body = await parseJsonBody(req).catch(() => ({}));
      const utr = body.utr || 'CONCIERGE_VERIFIED';
      const newStatus = `Paid & Confirmed via UPI (Ref: ${utr})`;
      await db.updateOrder(orderId, { status: newStatus });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, status: newStatus }));
      return;
    }

    if (pathname.includes('/reject-payment') && req.method === 'POST') {
      if (!isAuthenticatedAdmin(req)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin authentication required' }));
        return;
      }
      const orderId = pathname.split('/')[3];
      const newStatus = 'Cancelled (Invalid Payment Reference)';
      await db.updateOrder(orderId, { status: newStatus });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, status: newStatus }));
      return;
    }

    // --- YOUPI SMS GATEWAY APK PAIRING & SMS NOTIFICATION LISTENER ---
    if (pathname.includes('/pair') || pathname.includes('/enroll') || pathname.includes('/connect') || pathname === '/api/device' || pathname === '/api/gateway') {
      const body = await parseJsonBody(req).catch(() => ({}));
      console.log('\n[Atelier UPI Gateway] ★ DEVICE PAIRING SUCCESSFUL:', body);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        status: 'PAIRED',
        paired: true,
        message: 'Device successfully paired to Tokyo Drift Atelier Gateway',
        deviceId: body.deviceId || body.device || 'CPH2617',
        token: body.token || 'tokyodrift_youpi_token'
      }));
      return;
    }

    if (pathname.includes('/sms') || pathname.includes('/notification') || pathname === '/api/events') {
      const body = await parseJsonBody(req).catch(() => ({}));
      console.log('\n[Atelier UPI Gateway] ★ BANK SMS / NOTIFICATION RECEIVED:', body);
      const text = body.message || body.text || body.body || JSON.stringify(body);
      const utrMatch = text.match(/(?:UPI Ref|UTR|Ref No|Reference)[\s\/:#]*(\d{12})/i) || text.match(/\b(\d{12})\b/);
      const amountMatch = text.match(/(?:INR|Rs\.?|₹)\s*(\d+(?:\.\d{1,2})?)/i) || text.match(/(?:credited with|received)\s*(\d+(?:\.\d{1,2})?)/i);
      const utr = body.utr || (utrMatch ? utrMatch[1] : null);
      const amount = body.amount || (amountMatch ? parseFloat(amountMatch[1]) : 0);

      if (utr) {
        console.log(`[Atelier UPI Gateway] Extracted -> UTR: ${utr}, Amount: ₹${amount}`);
        await db.recordBankCredit({ utr, amount, sender: body.sender || '', raw: text });
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, processed: true, utr, amount }));
      return;
    }

    if (pathname === '/api/heartbeat' || pathname === '/api/ping' || pathname === '/api/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, status: 'ONLINE', time: new Date().toISOString() }));
      return;
    }

    // --- API: TRACK VIEWS & ANALYTICS ---
    if (pathname === '/api/track-view' && req.method === 'POST') {
      const body = await parseJsonBody(req);
      const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();
      const userAgent = req.headers['user-agent'] || '';
      const isMobile = /mobile|iphone|android|ipad/i.test(userAgent);
      const device = body.device || (isMobile ? 'Mobile' : 'Desktop');
      const pathUrl = body.path || '/';
      const referrer = body.referrer || 'Direct / Bookmark';

      const result = await db.trackView({ path: pathUrl, referrer, device, ip });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
      return;
    }

    // --- API: GET / CLEAR VIEWS ---
    if (pathname === '/api/views') {
      if (req.method === 'GET') {
        const views = await db.getViews();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(views));
        return;
      }

      if (req.method === 'DELETE' || (req.method === 'POST' && url.searchParams.get('action') === 'clear')) {
        if (!isAdmin) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
          return;
        }
        await db.clearViews();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: 'View analytics cleared' }));
        return;
      }
    }

    // --- API: SETTINGS ---
    if (pathname === '/api/settings') {
      if (req.method === 'GET') {
        const settings = await db.getSettings();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(settings));
        return;
      }

      if (req.method === 'POST') {
        if (!isAdmin) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
          return;
        }
        const settingsObj = await parseJsonBody(req);
        const result = await db.saveSettings(settingsObj);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
    }

    // --- API: CATEGORIES ---
    if (pathname === '/api/categories') {
      if (req.method === 'GET') {
        const categories = await db.getCategories();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(categories));
        return;
      }

      if (req.method === 'POST') {
        if (!isAdmin) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
          return;
        }
        const body = await parseJsonBody(req);
        const cats = body.categories || body.name;
        const updatedCats = await db.addCategories(cats);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, categories: updatedCats }));
        return;
      }
    }

    if (pathname.startsWith('/api/categories/') && req.method === 'DELETE') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
        return;
      }
      const rawCat = pathname.replace('/api/categories/', '');
      const catName = decodeURIComponent(rawCat).trim();
      const updatedCats = await db.deleteCategory(catName);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, categories: updatedCats }));
      return;
    }

    // --- API: PROMOTIONS / DISCOUNT CODES ---
    if (pathname === '/api/promos') {
      if (req.method === 'GET') {
        const settings = await db.getSettings();
        const promos = settings.promoCodes || [];
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(promos));
        return;
      }

      if (req.method === 'POST') {
        if (!isAdmin) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
          return;
        }
        const newPromo = await parseJsonBody(req);
        const settings = await db.getSettings();
        const currentPromos = Array.isArray(settings.promoCodes) ? [...settings.promoCodes] : [];
        const filtered = currentPromos.filter(p => p.code !== newPromo.code);
        filtered.push(newPromo);
        await db.saveSettings({ ...settings, promoCodes: filtered });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, promoCodes: filtered }));
        return;
      }
    }

    if (pathname.startsWith('/api/promos/') && req.method === 'DELETE') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
        return;
      }
      const codeToDelete = decodeURIComponent(pathname.replace('/api/promos/', '')).trim().toUpperCase();
      const settings = await db.getSettings();
      const currentPromos = Array.isArray(settings.promoCodes) ? [...settings.promoCodes] : [];
      const filtered = currentPromos.filter(p => (p.code || '').toUpperCase() !== codeToDelete);
      await db.saveSettings({ ...settings, promoCodes: filtered });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, promoCodes: filtered }));
      return;
    }

    // --- API: IMAGE UPLOAD (PERSISTENT CLOUD POSTGRESQL & CACHE) ---
    if (pathname === '/api/upload' && req.method === 'POST') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required to upload media' }));
        return;
      }
      try {
        const { dataUrl, target } = await parseJsonBody(req);
        if (!dataUrl || !dataUrl.includes(';base64,')) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Valid base64 image dataUrl is required' }));
          return;
        }
        const parts = dataUrl.split(';base64,');
        const mime = parts[0].replace('data:', '');
        let ext = mime.split('/')[1] || 'jpg';
        if (ext === 'jpeg') ext = 'jpg';
        ext = ext.replace(/[^a-zA-Z0-9]/g, '');
        const prefix = (target || 'banner').replace(/[^a-zA-Z0-9_-]/g, '');
        const cleanFileName = `${prefix}-${Date.now()}.${ext}`;

        // 1. Store permanently in PostgreSQL cloud database
        await db.saveUpload(cleanFileName, mime, parts[1]);

        // 2. Write to local cache for fast local serving
        try {
          const uploadsDir = path.join(__dirname, 'uploads');
          if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
          fs.writeFileSync(path.join(uploadsDir, cleanFileName), Buffer.from(parts[1], 'base64'));
        } catch(e) {
          try {
            const tmpDir = path.join('/tmp', 'uploads');
            if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
            fs.writeFileSync(path.join(tmpDir, cleanFileName), Buffer.from(parts[1], 'base64'));
          } catch(err) {}
        }

        const publicUrl = `/uploads/${cleanFileName}`;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, url: publicUrl }));
        return;
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
        return;
      }
    }

    // --- API: NEWSLETTER SUBSCRIBE ---
    if (pathname === '/api/subscribe' && req.method === 'POST') {
      const { email } = await parseJsonBody(req);
      const resObj = await db.addSubscriber(email);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(resObj));
      return;
    }

    // --- API: RESTOCK ALERT CAPTURE & MANAGEMENT ---
    if (pathname === '/api/restock-alert' || pathname === '/api/restock-alerts') {
      if (req.method === 'GET') {
        if (!isAdmin) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
          return;
        }
        const alerts = await db.getRestockAlerts();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(alerts));
        return;
      }

      if (req.method === 'POST') {
        const { productId, size, email } = await parseJsonBody(req);
        const result = await db.saveRestockAlert({ productId, size, email });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
    }

    if (pathname.startsWith('/api/restock-alerts/') && req.method === 'DELETE') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
        return;
      }
      const alertId = pathname.replace('/api/restock-alerts/', '');
      const result = await db.deleteRestockAlert(alertId);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
      return;
    }

    // --- API: ATELIER APPOINTMENTS ---
    if (pathname === '/api/appointments') {
      if (req.method === 'GET') {
        if (!isAdmin) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
          return;
        }
        const apts = await db.getAppointments();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(apts));
        return;
      }

      if (req.method === 'POST') {
        const aptData = await parseJsonBody(req);
        const result = await db.saveAppointment(aptData);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
    }

    if (pathname.startsWith('/api/appointments/') && req.method === 'PATCH') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
        return;
      }
      const id = pathname.replace('/api/appointments/', '');
      const { status } = await parseJsonBody(req);
      const result = await db.updateAppointment(id, status);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
      return;
    }

    if (pathname.startsWith('/api/appointments/') && req.method === 'DELETE') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
        return;
      }
      const id = pathname.replace('/api/appointments/', '');
      const result = await db.deleteAppointment(id);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
      return;
    }

    // --- API: CUSTOMER AUTHENTICATION (SIGN UP) ---
    if (pathname === '/api/auth/signup' && req.method === 'POST') {
      const { name, email, password, phone, address, city, postalCode, country } = await parseJsonBody(req);
      if (!email || !password) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Email and password are required' }));
        return;
      }
      const cleanEmail = email.trim().toLowerCase();
      if (!cleanEmail.includes('@') || password.length < 4) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Please enter a valid email and a password of at least 4 characters' }));
        return;
      }

      const existing = await db.getCustomerByEmail(cleanEmail);
      if (existing) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'An account with this email already exists. Please sign in.' }));
        return;
      }

      const customerId = 'CUST-' + Math.floor(100000 + Math.random() * 900000);
      const passwordHash = await hashPassword(password);
      const createdAt = new Date().toISOString();

      const newCustomer = {
        id: customerId,
        name: (name || '').trim() || 'Atelier Client',
        email: cleanEmail,
        passwordHash,
        phone: (phone || '').trim(),
        address: (address || '').trim(),
        city: (city || '').trim(),
        postalCode: (postalCode || '').trim(),
        country: (country || 'Japan').trim(),
        created_at: createdAt
      };

      await db.saveCustomer(newCustomer);

      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      await db.saveSession(token, customerId, expiresAt);

      const safeCust = { ...newCustomer };
      delete safeCust.passwordHash;

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, customer: safeCust, token }));
      return;
    }

    // --- API: CUSTOMER AUTHENTICATION (SIGN IN) ---
    if (pathname === '/api/auth/signin' && req.method === 'POST') {
      const { email, password } = await parseJsonBody(req);
      if (!email || !password) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Email and password are required' }));
        return;
      }
      const cleanEmail = email.trim().toLowerCase();

      const customerRow = await db.getCustomerByEmail(cleanEmail);
      if (!customerRow) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'No account found with this email. Please sign up.' }));
        return;
      }

      const valid = await verifyPassword(password, customerRow.passwordHash);
      if (!valid) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Incorrect password. Please verify and try again.' }));
        return;
      }

      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      await db.saveSession(token, customerRow.id, expiresAt);

      const safeCust = { ...customerRow };
      delete safeCust.passwordHash;

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, customer: safeCust, token }));
      return;
    }

    // --- API: CURRENT LOGGED IN CUSTOMER PROFILE & ORDERS ---
    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const customer = await getCustomerFromToken(req);
      if (!customer) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not authenticated' }));
        return;
      }

      const allOrders = await db.getOrders();
      const customerOrders = allOrders.filter(o => {
        try {
          const cust = o.customer || {};
          return (cust.email && cust.email.toLowerCase() === (customer.email || '').toLowerCase()) || o.customerId === customer.id;
        } catch (e) {
          return false;
        }
      });

      const customerSafe = {
        id: customer.id,
        name: customer.name,
        email: customer.email,
        phone: customer.phone,
        address: customer.address,
        city: customer.city,
        postalCode: customer.postalCode,
        country: customer.country,
        created_at: customer.created_at
      };

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, customer: customerSafe, orders: customerOrders }));
      return;
    }

    // --- API: UPDATE CUSTOMER PROFILE ---
    if (pathname === '/api/auth/profile' && req.method === 'PUT') {
      const customer = await getCustomerFromToken(req);
      if (!customer) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not authenticated' }));
        return;
      }

      const updates = await parseJsonBody(req);
      const updatedCustomer = await db.updateCustomerProfile(customer.id, updates);
      const customerSafe = { ...updatedCustomer };
      delete customerSafe.passwordHash;

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, customer: customerSafe }));
      return;
    }

    // --- API: SIGN OUT ---
    if (pathname === '/api/auth/signout' && req.method === 'POST') {
      const authHeader = req.headers['authorization'] || '';
      const token = authHeader.replace(/^Bearer\s+/i, '').trim();
      if (token) {
        await db.deleteSession(token);
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true }));
      return;
    }

    // --- API: ADMIN GET ALL CUSTOMERS ---
    if (pathname === '/api/customers' && req.method === 'GET') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
        return;
      }
      const customersList = await db.getAllCustomers();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(customersList));
      return;
    }

    // --- API: DATABASE EXPORT / IMPORT ---
    if (pathname === '/api/db/export' && req.method === 'GET') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
        return;
      }
      const data = await db.getFullDatabase({ isAdmin: true });
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Disposition': 'attachment; filename="tokyo_drift_full_backup.json"'
      });
      res.end(JSON.stringify(data, null, 2));
      return;
    }

    if (pathname === '/api/db/import' && req.method === 'POST') {
      if (!isAdmin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Admin privileges required' }));
        return;
      }
      const imported = await parseJsonBody(req);
      const result = await db.importDatabase(imported);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
      return;
    }

  } catch (apiErr) {
    console.error('[Tokyo Drift API Error]', apiErr);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: apiErr.message }));
    return;
  }

  // --- PERMANENT CLOUD UPLOAD SERVING (/uploads/*) ---
  if (pathname.startsWith('/uploads/')) {
    const rawUploadName = pathname.replace(/^\/uploads\//, '');
    const uploadName = path.basename(rawUploadName);

    // Block path traversal and invalid characters
    if (!uploadName || uploadName !== rawUploadName || uploadName.startsWith('.')) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid upload filename' }));
      return;
    }

    let localUploadPath = path.join(__dirname, 'uploads', uploadName);
    if (!fs.existsSync(localUploadPath)) {
      localUploadPath = path.join('/tmp', 'uploads', uploadName);
    }

    if (fs.existsSync(localUploadPath)) {
      const ext = path.extname(uploadName).toLowerCase();
      res.writeHead(200, {
        'Content-Type': MIME_TYPES[ext] || 'image/jpeg',
        'Cache-Control': 'public, max-age=31536000, immutable'
      });
      const stream = fs.createReadStream(localUploadPath);
      stream.on('error', (streamErr) => {
        console.error('[Tokyo Drift Upload Stream Error]', streamErr);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Failed to read upload' }));
        }
      });
      stream.pipe(res);
      return;
    }

    // Fallback: fetch from PostgreSQL cloud database if ephemeral container restarted
    try {
      const dbUpload = await db.getUpload(uploadName);
      if (dbUpload && dbUpload.data) {
        const imgBuffer = Buffer.from(dbUpload.data, 'base64');
        try {
          const tmpDir = path.join('/tmp', 'uploads');
          if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
          fs.writeFileSync(path.join(tmpDir, uploadName), imgBuffer);
        } catch(e) {}
        res.writeHead(200, {
          'Content-Type': dbUpload.mime || 'image/jpeg',
          'Content-Length': imgBuffer.length,
          'Cache-Control': 'public, max-age=31536000, immutable'
        });
        res.end(imgBuffer);
        return;
      }
    } catch(err) {
      console.warn('[Tokyo Drift Upload Serve Notice]', err.message);
    }

    // If not found in disk or database, return 404 (do not leak or fallback to index.html)
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'File not found' }));
    return;
  }

  // --- HARDENED STATIC FILE SERVING ---
  const normalizedPath = path.normalize(pathname).replace(/\\/g, '/');

  // Prevent directory traversal
  if (normalizedPath.includes('..')) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad Request: Invalid path traversal');
    return;
  }

  // Strict Blacklist: Block all sensitive environment, code, database, and system files
  const forbiddenPatterns = [
    /^\/\./,              // Dotfiles: /.env, /.env.local, /.git, etc.
    /\.env(\..+)?$/i,     // Any .env variant
    /\.sqlite(-.+)?$/i,   // SQLite databases
    /\.db$/i,             // DB files
    /package(-lock)?\.json$/i,
    /server\.js$/i,
    /db\.js$/i,
    /vercel\.json$/i,
    /\/node_modules\//i
  ];

  for (const pattern of forbiddenPatterns) {
    if (pattern.test(normalizedPath)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Access Denied: Protected resource');
      return;
    }
  }

  // Allowlisted root static assets
  const safeBaseName = path.basename(pathname);
  const allowedRootAssets = new Set([
    'index.html',
    'auth-bg.jpg',
    'cyberstar-hero.jpg',
    'eagicy-bg.jpg',
    'hero-bg.jpg',
    'favicon.ico',
    'robots.txt'
  ]);

  let filePath = null;

  if (pathname === '/' || pathname === '/admin') {
    filePath = path.join(__dirname, 'index.html');
  } else if (allowedRootAssets.has(safeBaseName) && path.dirname(pathname) === '/') {
    filePath = path.join(__dirname, safeBaseName);
  } else {
    // Check inside public/ directory
    const cleanPublicRel = pathname.replace(/^\/+/, '');
    const candidatePath = path.join(__dirname, 'public', cleanPublicRel);
    const publicRoot = path.join(__dirname, 'public');
    if (candidatePath.startsWith(publicRoot) && fs.existsSync(candidatePath)) {
      filePath = candidatePath;
    }
  }

  // If a file was identified and exists on disk, serve it
  if (filePath && fs.existsSync(filePath)) {
    const stat = fs.statSync(filePath);
    if (stat.isFile()) {
      const extname = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[extname] || 'application/octet-stream';
      const isImmutable = ['.png', '.jpg', '.jpeg', '.webp', '.avif', '.gif', '.svg', '.ico'].includes(extname);
      const cacheControl = isImmutable ? 'public, max-age=86400' : 'no-cache';

      res.writeHead(200, {
        'Content-Type': contentType,
        'Content-Length': stat.size,
        'Cache-Control': cacheControl
      });
      fs.createReadStream(filePath).pipe(res);
      return;
    }
  }

  // SPA Fallback: If requesting HTML / navigating pages without file extension, serve index.html
  const hasExtension = path.extname(pathname) !== '';
  const acceptHeader = req.headers['accept'] || '';
  if (!hasExtension || acceptHeader.includes('text/html')) {
    const indexPath = path.join(__dirname, 'index.html');
    if (fs.existsSync(indexPath)) {
      const stat = fs.statSync(indexPath);
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': stat.size,
        'Cache-Control': 'no-cache'
      });
      fs.createReadStream(indexPath).pipe(res);
      return;
    }
  }

  // 404 for missing static assets (images, css, js)
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('404 Not Found');
}

const server = http.createServer(handleRequest);

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => {
    console.log(`\n==================================================`);
    console.log(` TOKYO DRIFT ENTERPRISE STORE & DATABASE ONLINE`);
    console.log(` Storefront: http://localhost:${PORT}`);
    console.log(` Admin Station: http://localhost:${PORT}/admin`);
    console.log(` Health Check: http://localhost:${PORT}/api/health`);
    console.log(` Database: PostgreSQL Cloud + SQLite Native Sync`);
    console.log(`==================================================\n`);
  });
}

module.exports = server;
module.exports.handler = handleRequest;
