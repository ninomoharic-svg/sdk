// App-proxy + webhook backend for the customer dashboard.
// Handles: support messages, return requests, design review approvals,
// and referral tracking (code generation + earnings on referred orders).
// All state lives in customer metafields (namespace "dashboard").
//
// Setup:
//   1. Create a custom app in Shopify Admin (Settings > Apps > Develop apps),
//      grant it "read_customers", "write_customers", "read_discounts",
//      "write_discounts" and "read_orders" Admin API scopes. Copy its
//      Admin API access token into SHOPIFY_ADMIN_TOKEN.
//   2. Add an App proxy on that custom app:
//        Subpath prefix: apps  |  Subpath: dashboard
//        Proxy URL: https://<where-you-deploy-this>/proxy
//      Shopify forwards https://yourstore.com/apps/dashboard/* here as
//      /proxy/*, signed with the app's API secret (SHOPIFY_API_SECRET).
//   3. Register two webhooks (Admin > Notifications, or via API) pointing
//      at this server, each with its own signing secret:
//        customers/create -> https://<host>/webhooks/customers/create
//        orders/paid      -> https://<host>/webhooks/orders/paid
//      Shopify signs webhooks with the WEBHOOK secret shown when you
//      create them (same secret for both if created together) — set it
//      as SHOPIFY_WEBHOOK_SECRET.
//   4. Design reviews are added by staff, not customers — call
//      POST /admin/design-reviews (protected by ADMIN_SECRET) when a
//      proof is ready, e.g. from a Shopify Flow "Send HTTP request" step.
//
// Env vars required:
//   SHOPIFY_STORE_DOMAIN    e.g. bkjhti-kg.myshopify.com
//   SHOPIFY_CLIENT_ID       the app's Client ID (Dev Dashboard > App settings)
//   SHOPIFY_ADMIN_TOKEN     Admin API access token — obtained by visiting
//                           /auth once after deploying (see below), NOT
//                           available as a static value in Shopify admin
//                           for apps created via the new Dev Dashboard flow
//   SHOPIFY_API_SECRET      the app's Client Secret (also used for
//                           app-proxy signature verification)
//   SHOPIFY_WEBHOOK_SECRET  webhook signing secret
//   ADMIN_SECRET            a secret you invent, required as
//                           "Authorization: Bearer <ADMIN_SECRET>" on
//                           /admin/* endpoints
//   REFERRAL_DISCOUNT_PCT   % off the discount code gives the referred
//                           shopper, default 10
//   REFERRAL_EARNING_PCT    % of order subtotal credited to the referrer,
//                           default 10
//
// One-time OAuth step to obtain SHOPIFY_ADMIN_TOKEN:
//   1. Deploy this server once (SHOPIFY_ADMIN_TOKEN can be blank so far).
//   2. In the Dev Dashboard app config, add this server's
//      "<host>/auth/callback" to Allowed redirection URL(s), and set
//      App URL to "<host>/auth".
//   3. Visit https://<host>/auth in a browser while logged into the store
//      admin. It redirects through Shopify's consent screen and back to
//      /auth/callback, which prints the access token on screen.
//   4. Copy that token into SHOPIFY_ADMIN_TOKEN and redeploy.

const express = require('express');
const crypto = require('crypto');
const fetch = require('node-fetch');

const {
  SHOPIFY_STORE_DOMAIN,
  SHOPIFY_CLIENT_ID,
  SHOPIFY_ADMIN_TOKEN,
  SHOPIFY_API_SECRET,
  SHOPIFY_WEBHOOK_SECRET,
  ADMIN_SECRET,
  REFERRAL_DISCOUNT_PCT = '10',
  REFERRAL_EARNING_PCT = '10',
  PORT = 3000,
} = process.env;

const OAUTH_SCOPES = 'read_customers,write_customers,read_discounts,write_discounts,read_orders';

const app = express();
app.use(express.urlencoded({ extended: true }));
// Webhooks need the raw body to verify HMAC; capture it alongside the parsed JSON.
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));

// --- Verify every app-proxy request actually came from Shopify ---
function verifyProxySignature(req, res, next) {
  const { signature, ...rest } = req.query;
  if (!signature) return res.status(401).send('Missing signature');

  const message = Object.keys(rest)
    .sort()
    .map((key) => `${key}=${[].concat(rest[key]).join(',')}`)
    .join('');

  const digest = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(message)
    .digest('hex');

  if (digest !== signature) return res.status(401).send('Invalid signature');
  next();
}

app.use('/proxy', verifyProxySignature);

// TEMPORARY: verifies SHOPIFY_ADMIN_TOKEN actually works. Remove after testing.
app.get('/debug-token-check', async (req, res) => {
  try {
    const resp = await fetch(`https://${SHOPIFY_STORE_DOMAIN}/admin/api/2024-10/shop.json`, {
      headers: { 'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN },
    });
    const data = await resp.json();
    res.json({ ok: resp.ok, shopName: data.shop ? data.shop.name : null, status: resp.status });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --- Verify webhook requests came from Shopify ---
function verifyWebhookSignature(req, res, next) {
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  if (!hmac || !req.rawBody) return res.status(401).send('Missing signature');

  const digest = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest('base64');

  if (digest !== hmac) return res.status(401).send('Invalid signature');
  next();
}

app.use('/webhooks', verifyWebhookSignature);

// --- Simple bearer-token auth for staff-triggered endpoints ---
function verifyAdminSecret(req, res, next) {
  const auth = req.get('Authorization') || '';
  if (auth !== `Bearer ${ADMIN_SECRET}`) return res.status(401).send('Unauthorized');
  next();
}

app.use('/admin', verifyAdminSecret);

// --- One-time OAuth flow to obtain an Admin API access token ---
// (see the setup comment at the top of this file)
app.get('/auth', (req, res) => {
  const redirectUri = `https://${req.get('host')}/auth/callback`;
  const state = crypto.randomBytes(16).toString('hex');
  const authorizeUrl =
    `https://${SHOPIFY_STORE_DOMAIN}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_CLIENT_ID}` +
    `&scope=${encodeURIComponent(OAUTH_SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;
  res.redirect(authorizeUrl);
});

app.get('/auth/callback', async (req, res) => {
  const { code, hmac, shop } = req.query;
  if (!code || shop !== SHOPIFY_STORE_DOMAIN) return res.status(400).send('Invalid callback');

  const { hmac: _hmac, ...rest } = req.query;
  const message = Object.keys(rest)
    .sort()
    .map((key) => `${key}=${rest[key]}`)
    .join('&');
  const digest = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(message).digest('hex');
  if (digest !== hmac) return res.status(401).send('Invalid HMAC');

  const resp = await fetch(`https://${SHOPIFY_STORE_DOMAIN}/admin/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: SHOPIFY_CLIENT_ID,
      client_secret: SHOPIFY_API_SECRET,
      code,
    }),
  });
  const { access_token } = await resp.json();

  res.send(
    `<p>Copy this into the <code>SHOPIFY_ADMIN_TOKEN</code> environment variable, then redeploy:</p>` +
    `<pre>${access_token}</pre>`
  );
});

// --- Shopify Admin GraphQL helper ---
async function adminGraphQL(query, variables) {
  const resp = await fetch(
    `https://${SHOPIFY_STORE_DOMAIN}/admin/api/2024-10/graphql.json`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN,
      },
      body: JSON.stringify({ query, variables }),
    }
  );
  const json = await resp.json();
  if (json.errors) throw new Error(JSON.stringify(json.errors));
  return json.data;
}

async function getMetafieldList(customerId, key) {
  const data = await adminGraphQL(
    `query($id: ID!, $key: String!) {
      customer(id: $id) {
        metafield(namespace: "dashboard", key: $key) { id value }
      }
    }`,
    { id: customerId, key }
  );
  const mf = data.customer && data.customer.metafield;
  return mf ? JSON.parse(mf.value) : [];
}

async function setMetafieldList(customerId, key, list) {
  await setMetafields([{ ownerId: customerId, key, type: 'json', value: JSON.stringify(list) }]);
}

async function setMetafields(fields) {
  await adminGraphQL(
    `mutation($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) {
        userErrors { field message }
      }
    }`,
    {
      metafields: fields.map((f) => ({
        ownerId: f.ownerId,
        namespace: 'dashboard',
        key: f.key,
        type: f.type,
        value: f.value,
      })),
    }
  );
}

async function getMetafieldNumber(customerId, key) {
  const data = await adminGraphQL(
    `query($id: ID!, $key: String!) {
      customer(id: $id) {
        metafield(namespace: "dashboard", key: $key) { value }
      }
    }`,
    { id: customerId, key }
  );
  const mf = data.customer && data.customer.metafield;
  return mf ? Number(mf.value) : 0;
}

// Referral code encodes the customer's numeric id directly, so it decodes
// back to a customer gid with no reverse-lookup/database needed.
function referralCodeForCustomer(numericId) {
  return `REF-${BigInt(numericId).toString(36).toUpperCase()}`;
}

function customerIdFromReferralCode(code) {
  const match = /^REF-([0-9A-Z]+)$/.exec(code || '');
  if (!match) return null;
  const id = parseInt(match[1], 36);
  if (!Number.isFinite(id)) return null;
  return `gid://shopify/Customer/${id}`;
}

// Shopify app proxy forwards the logged-in customer's id as logged_in_customer_id
function customerGid(req) {
  const id = req.query.logged_in_customer_id;
  if (!id) return null;
  return `gid://shopify/Customer/${id}`;
}

async function createReferralDiscountCode(code) {
  await adminGraphQL(
    `mutation($basicCodeDiscount: DiscountCodeBasicInput!) {
      discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
        userErrors { field message }
      }
    }`,
    {
      basicCodeDiscount: {
        title: code,
        code,
        startsAt: new Date().toISOString(),
        customerSelection: { all: true },
        customerGets: {
          value: { percentage: Number(REFERRAL_DISCOUNT_PCT) / 100 },
          items: { all: true },
        },
        appliesOncePerCustomer: true,
      },
    }
  );
}

// --- POST /proxy/messages ---
app.post('/proxy/messages', async (req, res) => {
  const gid = customerGid(req);
  if (!gid) return res.status(401).send('Not logged in');

  const body = (req.body.message || '').trim();
  if (!body) return res.status(400).send('Message required');

  const messages = await getMetafieldList(gid, 'messages');
  messages.push({
    from: 'customer',
    body,
    date: new Date().toISOString().slice(0, 10),
  });
  await setMetafieldList(gid, 'messages', messages);

  res.json({ ok: true });
});

// --- POST /proxy/returns ---
app.post('/proxy/returns', async (req, res) => {
  const gid = customerGid(req);
  if (!gid) return res.status(401).send('Not logged in');

  const { order_name, reason } = req.body;
  if (!order_name || !reason) return res.status(400).send('order_name and reason required');

  const returns = await getMetafieldList(gid, 'returns');
  returns.push({
    order_name,
    reason,
    status: 'requested',
    date: new Date().toISOString().slice(0, 10),
  });
  await setMetafieldList(gid, 'returns', returns);

  res.json({ ok: true });
});

// --- POST /proxy/reviews/:index/approve ---
app.post('/proxy/reviews/:index/approve', async (req, res) => {
  const gid = customerGid(req);
  if (!gid) return res.status(401).send('Not logged in');

  const index = Number(req.params.index);
  const reviews = await getMetafieldList(gid, 'design_reviews');
  if (!reviews[index]) return res.status(404).send('Review not found');

  reviews[index].status = 'approved';
  await setMetafieldList(gid, 'design_reviews', reviews);
  res.json({ ok: true });
});

// --- POST /proxy/reviews/:index/changes ---
app.post('/proxy/reviews/:index/changes', async (req, res) => {
  const gid = customerGid(req);
  if (!gid) return res.status(401).send('Not logged in');

  const index = Number(req.params.index);
  const note = (req.body.note || '').trim();
  const reviews = await getMetafieldList(gid, 'design_reviews');
  if (!reviews[index]) return res.status(404).send('Review not found');

  reviews[index].status = 'changes_requested';
  reviews[index].customer_note = note;
  await setMetafieldList(gid, 'design_reviews', reviews);
  res.json({ ok: true });
});

// --- Webhook: customers/create -> assign a referral code + discount code ---
app.post('/webhooks/customers/create', async (req, res) => {
  try {
    const customer = req.body;
    const gid = `gid://shopify/Customer/${customer.id}`;
    const code = referralCodeForCustomer(customer.id);

    await createReferralDiscountCode(code);
    await setMetafields([{ ownerId: gid, key: 'referral_code', type: 'single_line_text_field', value: code }]);

    res.status(200).send('ok');
  } catch (err) {
    console.error(err);
    res.status(500).send('error');
  }
});

// --- Webhook: orders/paid -> credit the referrer, if a referral code was used ---
app.post('/webhooks/orders/paid', async (req, res) => {
  try {
    const order = req.body;
    const codes = (order.discount_codes || []).map((d) => d.code);
    const referralCode = codes.find((c) => /^REF-[0-9A-Z]+$/.test(c || ''));

    if (referralCode) {
      const referrerGid = customerIdFromReferralCode(referralCode);
      if (referrerGid) {
        const subtotal = Number(order.subtotal_price || order.total_price || 0);
        const earning = Math.round(subtotal * (Number(REFERRAL_EARNING_PCT) / 100) * 100) / 100;

        const currentEarnings = await getMetafieldNumber(referrerGid, 'referral_earnings');
        const referrals = await getMetafieldList(referrerGid, 'referrals');
        referrals.push({ order_name: order.name, earning, date: new Date().toISOString().slice(0, 10) });

        await setMetafields([
          { ownerId: referrerGid, key: 'referral_earnings', type: 'number_decimal', value: String(currentEarnings + earning) },
        ]);
        await setMetafieldList(referrerGid, 'referrals', referrals);
      }
    }

    res.status(200).send('ok');
  } catch (err) {
    console.error(err);
    res.status(500).send('error');
  }
});

// --- POST /admin/design-reviews -> staff pushes a new proof for a customer ---
// Body: { customer_id: <numeric Shopify customer id>, order_name, image_url }
app.post('/admin/design-reviews', async (req, res) => {
  const { customer_id, order_name, image_url } = req.body;
  if (!customer_id || !order_name) return res.status(400).send('customer_id and order_name required');

  const gid = `gid://shopify/Customer/${customer_id}`;
  const reviews = await getMetafieldList(gid, 'design_reviews');
  reviews.push({ order_name, image_url: image_url || null, status: 'pending' });
  await setMetafieldList(gid, 'design_reviews', reviews);

  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Dashboard proxy backend listening on :${PORT}`));
