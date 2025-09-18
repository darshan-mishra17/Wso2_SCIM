// Clean Asgardeo SCIM2 Integration Server
// ---------------------------------------
// Responsibilities:
// 1. Obtain OAuth2 access token (client credentials)
// 2. Provide helper functions to interact with Asgardeo SCIM2 User API
// 3. Expose a webhook endpoint (/frappe-webhook) that Frappe HR can call
//    - on_update  -> create or update a user
//    - on_trash   -> delete a user
// 4. Keep code minimal, clear, and production‑ready (logging + error handling)

require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

// ------------------------------
// Environment / Configuration
// ------------------------------
const {
	PORT = 3000,
	ASGARDEO_TENANT,              // e.g. mytenant
	ASGARDEO_CLIENT_ID,
	ASGARDEO_CLIENT_SECRET,
	ASGARDEO_SCIM_BASE,           // Optional override. If not set we derive.
	ASGARDEO_TOKEN_URL,           // Optional override of token endpoint
	ASGARDEO_INTROSPECT_URL,      // Optional: https://api.asgardeo.io/t/<tenant>/oauth2/introspect
	ASGARDEO_SCOPES,              // Space separated; overrides default scope set
	FRAPPE_WEBHOOK_SECRET         // Optional shared secret for webhook HMAC validation
} = process.env;

if (!ASGARDEO_TENANT || !ASGARDEO_CLIENT_ID || !ASGARDEO_CLIENT_SECRET) {
	console.error('❌ Missing required environment variables. Please set ASGARDEO_TENANT, ASGARDEO_CLIENT_ID, ASGARDEO_CLIENT_SECRET');
	process.exit(1);
}

// Default endpoints (multi-tenant public cloud pattern)
const TOKEN_URL = ASGARDEO_TOKEN_URL || `https://api.asgardeo.io/t/${ASGARDEO_TENANT}/oauth2/token`;
const SCIM_BASE = (ASGARDEO_SCIM_BASE || `https://api.asgardeo.io/t/${ASGARDEO_TENANT}/scim2/Users`).replace(/\/$/, '');
// Provide a default that includes internal_scim2 plus user management granular scopes.
const REQUESTED_SCOPES = (ASGARDEO_SCOPES && ASGARDEO_SCOPES.trim()) || 'internal_scim2 internal_user_mgt_create internal_user_mgt_view internal_user_mgt_update internal_user_mgt_delete';

const REQUIRED_SCOPE_KEYWORDS = ['internal_scim2','internal_user_mgt_create','internal_user_mgt_view','internal_user_mgt_update','internal_user_mgt_delete'];

// -------------
// App bootstrap
// -------------
const app = express();
// Capture raw body for optional HMAC validation
app.use(express.json({ verify:(req,res,buf)=>{ req.rawBody = buf; } }));

// Basic request logger (concise)
app.use((req, _res, next) => {
	console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
	next();
});

// ------------------------------
// OAuth2 Token (Client Credentials) with simple caching
// ------------------------------
let cachedToken = null; // { access_token, expires_at }

async function getAccessToken() {
	if (cachedToken && cachedToken.expires_at > Date.now() + 5000) { // 5s buffer
		return cachedToken.access_token;
	}

	const params = new URLSearchParams();
	params.append('grant_type', 'client_credentials');
	params.append('client_id', ASGARDEO_CLIENT_ID);
	params.append('client_secret', ASGARDEO_CLIENT_SECRET);
	params.append('scope', REQUESTED_SCOPES);

	try {
		const resp = await axios.post(TOKEN_URL, params, {
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
		});
		const { access_token, expires_in, scope } = resp.data;
		console.log('🔑 Obtained token. Requested scopes =>', REQUESTED_SCOPES);
		console.log('🔑 Returned scopes  =>', scope);
		// Quick advisory if any required scope is missing
		if (scope) {
			const returned = scope.split(/\s+/);
			const missing = REQUIRED_SCOPE_KEYWORDS.filter(s => !returned.includes(s));
			if (missing.length) {
				console.warn('⚠️ Missing expected scopes from token:', missing.join(', '), '\n   -> Check application role assignments & authorized scopes in Asgardeo');
			}
		}
		cachedToken = {
			access_token,
			expires_at: Date.now() + (expires_in * 1000)
		};
		return access_token;
	} catch (err) {
		console.error('❌ Failed to obtain access token:', err.response?.data || err.message);
		throw new Error('Unable to obtain access token');
	}
}

// ------------------------------
// SCIM Helper Functions
// ------------------------------
async function scimRequest(method, urlSuffix = '', data) {
	const token = await getAccessToken();
	const url = urlSuffix.startsWith('http') ? urlSuffix : `${SCIM_BASE}${urlSuffix}`; // urlSuffix may include /{id} or ?filter
	try {
		const resp = await axios({
			method,
			url,
			data,
			headers: { Authorization: `Bearer ${token}` }
		});
		return resp;
	} catch (err) {
		const payload = err.response?.data || err.message;
		console.error(`❌ SCIM ${method.toUpperCase()} ${url} failed:`, payload);
		if (err.response?.status === 403) {
			console.error('   🔎 403 Diagnostics:');
			console.error('   - Confirm application type is Service (client credentials)');
			console.error('   - Ensure all required internal_* scopes are added and saved');
			console.error('   - Ensure a role with User Management permissions is assigned to the application');
		}
		throw err;
	}
}

async function findUserByEmail(email) {
	if (!email) return null;
	const filter = encodeURIComponent(`userName eq "${email}"`);
	const resp = await scimRequest('get', `?filter=${filter}`);
	if (resp.data.totalResults > 0) {
		return resp.data.Resources[0];
	}
	return null;
}

async function createUser({ email, givenName = '', familyName = '', active = true }) {
	const body = {
		schemas: [
			'urn:ietf:params:scim:schemas:core:2.0:User',
			'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'
		],
		userName: email,
		name: { givenName, familyName },
		emails: [{ value: email, primary: true, type: 'work' }],
		active
	};

	const resp = await scimRequest('post', '', body);
	return { status: resp.status, user: resp.data };
}

async function updateUser(userId, { givenName, familyName, email, active }) {
	// Use SCIM PATCH (partial update is safer)
	const patchBody = {
		schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
		Operations: []
	};
	if (givenName !== undefined) patchBody.Operations.push({ op: 'replace', path: 'name.givenName', value: givenName });
	if (familyName !== undefined) patchBody.Operations.push({ op: 'replace', path: 'name.familyName', value: familyName });
	if (email !== undefined) patchBody.Operations.push({ op: 'replace', path: 'emails', value: [{ value: email, primary: true, type: 'work' }] });
	if (active !== undefined) patchBody.Operations.push({ op: 'replace', path: 'active', value: active });

	if (patchBody.Operations.length === 0) return { status: 204, message: 'Nothing to update' };

	const resp = await scimRequest('patch', `/${userId}`, patchBody);
	return { status: resp.status };
}

async function deleteUser(userId) {
	await scimRequest('delete', `/${userId}`);
	return { status: 204 };
}

// ------------------------------
// Webhook Endpoint (/frappe-webhook)
// ------------------------------
// Expected JSON body (example from Frappe):
// {
//   "first_name": "Jane",
//   "last_name": "Doe",
//   "user_id": "jane.doe@example.com",   // treated as email / username
//   "status": "Active" | "Inactive"
// }
// Header: x-frappe-event-type: on_update | on_trash

app.post('/frappe-webhook', async (req, res) => {
	const eventType = req.header('x-frappe-event-type');
	const { first_name, last_name, user_id, status } = req.body || {};

	// Optional HMAC validation (if secret set)
	if (FRAPPE_WEBHOOK_SECRET) {
		const sig = req.header('x-webhook-signature');
		if (!sig) {
			return res.status(401).json({ error: 'Missing webhook signature' });
		}
		const computed = crypto.createHmac('sha256', FRAPPE_WEBHOOK_SECRET).update(req.rawBody || '').digest('hex');
		if (computed !== sig) {
			return res.status(401).json({ error: 'Invalid webhook signature' });
		}
	}

	if (!eventType) {
		return res.status(400).json({ error: 'Missing x-frappe-event-type header' });
	}
	if (!user_id) {
		return res.status(400).json({ error: 'Missing user_id (email)' });
	}

	const email = user_id.trim();
	const active = status === 'Active';

	try {
		const existing = await findUserByEmail(email);

		if (eventType === 'on_update') {
			if (!existing) {
				console.log(`➡️ Creating new user ${email}`);
				const createResp = await createUser({
					email,
					givenName: first_name?.trim() || '',
					familyName: last_name?.trim() || '',
					active
				});

				// Optional: quick verification (search again). Some tenants may delay (202 Accepted).
				let verified = false;
				try {
					await new Promise(r => setTimeout(r, 1500));
					const check = await findUserByEmail(email);
						verified = !!check;
				} catch (_) { /* ignore */ }

				return res.status(201).json({
					message: 'User create triggered',
					scim_status: createResp.status,
					user: createResp.user,
					verified
				});
			} else {
				console.log(`🔄 Updating existing user ${email}`);
				const updateResp = await updateUser(existing.id, {
					givenName: first_name?.trim(),
					familyName: last_name?.trim(),
					email,
					active
				});
				return res.status(200).json({ message: 'User updated', scim_status: updateResp.status });
			}
		} else if (eventType === 'on_trash') {
			if (!existing) {
				return res.status(404).json({ error: 'User not found for deletion' });
			}
			await deleteUser(existing.id);
			return res.status(200).json({ message: 'User deleted' });
		} else {
			return res.status(400).json({ error: 'Unknown event type' });
		}
	} catch (err) {
		const status = err.response?.status;
		if (status === 403) {
			return res.status(403).json({
				error: 'SCIM forbidden (403)',
				details: err.response?.data,
				suggestions: [
					'Verify internal_scim2 and user management scopes are authorized',
					'Ensure role with Create/View/Update/Delete user permissions is assigned to the application',
					'Regenerate client secret only if app type changed',
					'Redeploy / restart after scope changes to clear cached token'
				]
			});
		}
		return res.status(500).json({ error: 'Internal error', details: err.response?.data || err.message });
	}
});

// Simple health endpoint
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// Debug token endpoint (forces new token fetch ignoring cache if ?fresh=1)
app.get('/debug-token', async (req, res) => {
		try {
				if (req.query.fresh === '1') { cachedToken = null; }
				const token = await getAccessToken();
				const parts = token.split('.');
				let decoded = {};
				if (parts.length === 3) {
						try { decoded = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8')); } catch { decoded = { error:'decode_failed' }; }
				}
				res.json({
						obtained_at: new Date().toISOString(),
						requested_scopes: REQUESTED_SCOPES,
						note: 'Returned scopes are printed in server stdout (token may be opaque)',
						expires_at: cachedToken?.expires_at,
						expires_in_ms: cachedToken ? cachedToken.expires_at - Date.now() : null,
						jwt_claims: decoded,
						token_format: parts.length === 3 ? 'jwt' : 'opaque',
						sample: token.slice(0,20) + '...'
				});
		} catch (e) {
				res.status(500).json({ error:'Failed to fetch token', details:e.message });
		}
});

// Token introspection (only if ASGARDEO_INTROSPECT_URL set and token is opaque)
if (ASGARDEO_INTROSPECT_URL) {
		app.get('/introspect-token', async (req, res) => {
				try {
						// Force new token if requested
						if (req.query.fresh === '1') { cachedToken = null; }
						const token = await getAccessToken();
						const body = new URLSearchParams();
						body.append('token', token);
						const basic = Buffer.from(`${ASGARDEO_CLIENT_ID}:${ASGARDEO_CLIENT_SECRET}`).toString('base64');
						const resp = await axios.post(ASGARDEO_INTROSPECT_URL, body, {
								headers: { 'Content-Type':'application/x-www-form-urlencoded', 'Authorization':`Basic ${basic}` }
						});
						res.json(resp.data);
				} catch (e) {
						res.status(500).json({ error:'Introspection failed', details: e.response?.data || e.message });
				}
		});
}

// Simple SCIM connectivity ping
app.get('/scim-ping', async (_req, res) => {
		try {
				const r = await scimRequest('get','?startIndex=1&count=1');
				res.json({ ok:true, status:r.status, total:r.data.totalResults });
		} catch (e) {
				res.status(e.response?.status || 500).json({ ok:false, error:e.response?.data || e.message });
		}
});

// -------------
// Start server
// -------------
app.listen(PORT, () => {
	console.log(`🚀 Server listening on port ${PORT}`);
	console.log(`SCIM Base: ${SCIM_BASE}`);
	console.log(`Requested Scopes: ${REQUESTED_SCOPES}`);
	if (FRAPPE_WEBHOOK_SECRET) console.log('Webhook HMAC validation ENABLED');
	if (ASGARDEO_INTROSPECT_URL) console.log('Introspection endpoint ENABLED');
});

// ------------------------------
// Export (optional for testing)
// ------------------------------
module.exports = app;

