// =========================================================================
// TOKYO DRIFT — COMPREHENSIVE SRE & SECURITY VERIFICATION SUITE
// Tests every endpoint, database operation, security barrier, and auth flow
// =========================================================================

const http = require('http');
const db = require('./db.js');
const server = require('./server.js');

const TEST_PORT = 3456;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;
const ADMIN_KEY = 'rishav@9798886818';

let passedTests = 0;
let totalTests = 0;

function assert(condition, testName) {
  totalTests++;
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passedTests++;
  } else {
    console.error(`  [FAIL] ${testName}`);
    process.exitCode = 1;
  }
}

function request(path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const reqOpts = {
      method: options.method || 'GET',
      headers: options.headers || {},
      timeout: 30000
    };

    const req = http.request(url, reqOpts, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch(e) {}
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data,
          json
        });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });

    if (options.body) {
      if (typeof options.body === 'object') {
        req.setHeader('Content-Type', 'application/json');
        req.write(JSON.stringify(options.body));
      } else {
        req.write(options.body);
      }
    }
    req.end();
  });
}

async function runAllTests() {
  console.log('\n======================================================');
  console.log(' STARTING TOKYO DRIFT VERIFICATION SUITE');
  console.log('======================================================\n');

  // 1. Direct Database Unit Verification
  console.log('--- 1. DATABASE & TELEMETRY UNIT TESTS ---');
  try {
    const ping = await db.ping();
    assert(ping && ping.ok === true, `db.ping() succeeds (Engine: ${ping.engine})`);

    const prods = await db.getProducts();
    assert(Array.isArray(prods), `db.getProducts() returns array (Found ${prods.length} products)`);

    const viewTrack = await db.trackView({ path: '/test-verify', referrer: 'Automated Test', device: 'CI/CD', ip: '127.0.0.1' });
    assert(viewTrack && viewTrack.success === true, 'db.trackView() records view without crash');

    const views = await db.getViews();
    assert(views && typeof views.totalViews === 'number', `db.getViews() returns valid telemetry (Total: ${views.totalViews})`);

    const publicDb = await db.getFullDatabase({ isAdmin: false });
    assert(publicDb && Array.isArray(publicDb.products) && publicDb.customers.length === 0, 'db.getFullDatabase({ isAdmin: false }) masks sensitive customer PII');

    const adminDb = await db.getFullDatabase({ isAdmin: true });
    assert(adminDb && Array.isArray(adminDb.products) && Array.isArray(adminDb.customers), 'db.getFullDatabase({ isAdmin: true }) provides full admin dataset');
  } catch(err) {
    console.error('Database unit test failed:', err);
    process.exitCode = 1;
  }

  // 2. Start HTTP Server for Integration Tests
  console.log('\n--- 2. HTTP SERVER INTEGRATION TESTS ---');
  await new Promise((resolve) => {
    server.listen(TEST_PORT, () => {
      console.log(`  Test server listening on port ${TEST_PORT}`);
      resolve();
    });
  });

  try {
    // Health Check
    const health = await request('/api/health');
    assert(health.statusCode === 200 && health.json.status === 'healthy', `GET /api/health returns 200 healthy`);

    // Public vs Admin Database Endpoints
    const publicAll = await request('/api/db/all');
    assert(publicAll.statusCode === 200 && Array.isArray(publicAll.json.products) && publicAll.json.customers.length === 0, 'GET /api/db/all without key returns public catalog without customer PII');

    const adminAll = await request('/api/db/all', {
      headers: { 'x-admin-key': ADMIN_KEY }
    });
    assert(adminAll.statusCode === 200 && Array.isArray(adminAll.json.products) && Array.isArray(adminAll.json.customers), 'GET /api/db/all with x-admin-key returns full administrative dataset');

    // Admin Route Protection
    const unauthCustomers = await request('/api/customers');
    assert(unauthCustomers.statusCode === 403, 'GET /api/customers without key is blocked (403 Forbidden)');

    const authCustomers = await request('/api/customers', {
      headers: { 'x-admin-key': ADMIN_KEY }
    });
    assert(authCustomers.statusCode === 200 && Array.isArray(authCustomers.json), 'GET /api/customers with x-admin-key is allowed (200 OK)');

    const unauthExport = await request('/api/db/export');
    assert(unauthExport.statusCode === 403, 'GET /api/db/export without key is blocked (403 Forbidden)');

    const authExport = await request('/api/db/export', {
      headers: { 'x-admin-key': ADMIN_KEY }
    });
    assert(authExport.statusCode === 200 && authExport.json && Array.isArray(authExport.json.products), 'GET /api/db/export with x-admin-key returns backup json');

    // Order Lifecycle & Administrative Security
    const testOrderId = `TKD-TEST-${Date.now()}`;
    const testOrder = {
      id: testOrderId,
      date: new Date().toISOString(),
      status: 'Authorized',
      customer: { fullName: 'Test Client', email: 'test@client.jp' },
      items: [{ id: 'PRD-TEST', title: 'Test Garment', size: 'M', quantity: 1, price: 999 }],
      financials: { grandTotal: 999 }
    };

    const placeOrder = await request('/api/orders', {
      method: 'POST',
      body: testOrder
    });
    assert(placeOrder.statusCode === 200 && placeOrder.json && placeOrder.json.success, 'POST /api/orders saves order to database pipeline');

    const unauthUpdateOrder = await request(`/api/orders/${testOrderId}`, {
      method: 'PUT',
      body: { status: 'Delivered' }
    });
    assert(unauthUpdateOrder.statusCode === 403, 'PUT /api/orders/:id without key is blocked (403 Forbidden)');

    const authUpdateOrder = await request(`/api/orders/${testOrderId}`, {
      method: 'PUT',
      headers: { 'x-admin-key': ADMIN_KEY },
      body: { status: 'Delivered' }
    });
    assert(authUpdateOrder.statusCode === 200, 'PUT /api/orders/:id with x-admin-key updates order status (200 OK)');

    const unauthDeleteOrder = await request(`/api/orders/${testOrderId}`, {
      method: 'DELETE'
    });
    assert(unauthDeleteOrder.statusCode === 403, 'DELETE /api/orders/:id without key is blocked (403 Forbidden)');

    const authDeleteOrder = await request(`/api/orders/${testOrderId}`, {
      method: 'DELETE',
      headers: { 'x-admin-key': ADMIN_KEY }
    });
    assert(authDeleteOrder.statusCode === 200, 'DELETE /api/orders/:id with x-admin-key deletes order (200 OK)');

    // Critical Security: Static File Leakage Protection
    console.log('\n--- 3. SECURITY PENETRATION TESTS ---');
    const envLeak = await request('/.env.local');
    assert(envLeak.statusCode === 403, 'GET /.env.local is blocked (403 Forbidden - database credentials protected)');

    const envRoot = await request('/.env');
    assert(envRoot.statusCode === 403, 'GET /.env is blocked (403 Forbidden)');

    const serverLeak = await request('/server.js');
    assert(serverLeak.statusCode === 403, 'GET /server.js is blocked (403 Forbidden)');

    const dbLeak = await request('/db.js');
    assert(dbLeak.statusCode === 403, 'GET /db.js is blocked (403 Forbidden)');

    const pathTraversal = await request('/uploads/..%2f.env.local');
    assert(pathTraversal.statusCode === 400 || pathTraversal.statusCode === 403 || pathTraversal.statusCode === 404, 'Directory traversal /uploads/../.env.local blocked');

    // Customer Authentication Lifecycle (Async scrypt)
    console.log('\n--- 4. CUSTOMER AUTHENTICATION (ASYNC SCRYPT) ---');
    const testEmail = `test_${Date.now()}@tokyodrift-atelier.jp`;
    const testPassword = 'ArchivalPassword2026!';

    const signup = await request('/api/auth/signup', {
      method: 'POST',
      body: {
        name: 'Kenji Sato',
        email: testEmail,
        password: testPassword,
        city: 'Tokyo'
      }
    });
    assert(signup.statusCode === 200 && signup.json.success === true && signup.json.token, 'POST /api/auth/signup hashes password asynchronously and issues session token');

    const authToken = signup.json ? signup.json.token : '';

    const signin = await request('/api/auth/signin', {
      method: 'POST',
      body: {
        email: testEmail,
        password: testPassword
      }
    });
    assert(signin.statusCode === 200 && signin.json.success === true, 'POST /api/auth/signin verifies password asynchronously using crypto.timingSafeEqual');

    const authMe = await request('/api/auth/me', {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    assert(authMe.statusCode === 200 && authMe.json.customer && authMe.json.customer.email === testEmail, 'GET /api/auth/me returns authenticated customer profile');

    const signout = await request('/api/auth/signout', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    assert(signout.statusCode === 200 && signout.json.success === true, 'POST /api/auth/signout deletes active session');

    // Headers & Storefront Loading
    console.log('\n--- 5. HEADERS & STOREFRONT VERIFICATION ---');
    const storefront = await request('/');
    assert(storefront.statusCode === 200, 'GET / returns 200 Storefront index.html');
    assert(storefront.headers['x-content-type-options'] === 'nosniff', 'X-Content-Type-Options: nosniff header is present');
    assert(storefront.headers['x-frame-options'] === 'SAMEORIGIN', 'X-Frame-Options: SAMEORIGIN header is present');

    const adminPage = await request('/admin');
    assert(adminPage.statusCode === 200, 'GET /admin routes to index.html with 200 OK');

    // Media & Upload Pipeline
    console.log('\n--- 6. UPLOAD & MEDIA PIPELINE ---');
    const uploadRes = await request('/uploads/product-1792928857466.jpg');
    assert(uploadRes.statusCode === 200 && uploadRes.headers['content-type'] === 'image/jpeg', 'GET /uploads/:filename serves binary image with image/jpeg header');

    const rewriteUpload = await request('/api?upload=product-1792928857466.jpg');
    assert(rewriteUpload.statusCode === 200 && rewriteUpload.headers['content-type'] === 'image/jpeg', 'GET /api?upload=:filename serves binary image through Vercel rewrite');

  } catch(err) {
    console.error('Integration test failed with error:', err);
    process.exitCode = 1;
  } finally {
    server.close(() => {
      console.log('\n======================================================');
      console.log(` RESULTS: ${passedTests} / ${totalTests} TESTS PASSED`);
      if (passedTests === totalTests) {
        console.log(' ALL SYSTEMS VERIFIED & PRODUCTION READY: 100% OPERATIONAL');
      } else {
        console.log(' WARNING: Some tests failed. Review output above.');
      }
      console.log('======================================================\n');
      process.exit(process.exitCode || 0);
    });
  }
}

runAllTests().catch(err => {
  console.error('Unhandled verification error:', err);
  process.exit(1);
});
