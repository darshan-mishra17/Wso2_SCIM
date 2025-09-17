// server.js
// Node.js Express server for integrating Frappe HR with WSO2 Asgardeo SCIM provisioning

require('dotenv').config();
const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Add support for form-encoded data

const PORT = process.env.PORT || 3000;
const ASGARDEO_TENANT = process.env.ASGARDEO_TENANT;
const ASGARDEO_CLIENT_ID = process.env.ASGARDEO_CLIENT_ID;
const ASGARDEO_CLIENT_SECRET = process.env.ASGARDEO_CLIENT_SECRET;

// Helper: Get Asgardeo SCIM base URL
const SCIM_BASE_URL = `https://api.asgardeo.io/t/${ASGARDEO_TENANT}/scim2/Users`;

// Helper: Get Asgardeo OAuth2 token endpoint
const TOKEN_URL = `https://api.asgardeo.io/t/${ASGARDEO_TENANT}/oauth2/token`;

// Helper: Create Basic Auth header for client credentials
function getBasicAuthHeader() {
    const creds = `${ASGARDEO_CLIENT_ID}:${ASGARDEO_CLIENT_SECRET}`;
    return 'Basic ' + Buffer.from(creds).toString('base64');
}

// 1. Asgardeo Authentication: Get OAuth2 access token
async function getAccessToken() {
    try {
        const params = new URLSearchParams();
        params.append('grant_type', 'client_credentials');
        
        // Try different scope combinations based on what's available in Asgardeo
        const scopeOptions = [
            'internal_user_mgt_create internal_user_mgt_list internal_user_mgt_view internal_user_mgt_delete internal_user_mgt_update', // Exact scopes from Asgardeo
            'internal_user_mgt_view internal_user_mgt_create internal_user_mgt_update internal_user_mgt_delete', // Original SCIM scopes
            '', // No specific scopes - use default granted scopes
            'openid', // Basic OpenID scope
        ];
        
        for (const scope of scopeOptions) {
            try {
                if (scope) {
                    params.set('scope', scope);
                    console.log(`🔄 Trying with scope: "${scope}"`);
                } else {
                    params.delete('scope');
                    console.log(`🔄 Trying without specific scope (using default)`);
                }
                
                console.log(`Requesting token from: ${TOKEN_URL}`);
                
                const response = await axios.post(
                    TOKEN_URL,
                    params,
                    {
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Authorization': getBasicAuthHeader(),
                        },
                    }
                );
                
                console.log('✅ Access token obtained successfully');
                console.log('📊 Token info:', {
                    token_type: response.data.token_type,
                    expires_in: response.data.expires_in,
                    scope: response.data.scope || 'default'
                });
                
                return response.data.access_token;
                
            } catch (scopeError) {
                console.log(`❌ Failed with scope "${scope}":`, scopeError.response?.status, scopeError.response?.data?.error_description);
                continue;
            }
        }
        
        throw new Error('All scope options failed');
        
    } catch (error) {
        console.error('❌ Error fetching Asgardeo access token:');
        console.error('Response status:', error.response?.status);
        console.error('Response data:', error.response?.data);
        throw error;
    }
}

// Test endpoint to debug SCIM access
app.get('/test-scim', async (req, res) => {
    try {
        console.log('🧪 Testing SCIM configuration...');
        const accessToken = await getAccessToken();
        
        // Test basic SCIM endpoint
        const testUrl = `${SCIM_BASE_URL}?count=1`;
        console.log(`Testing SCIM endpoint: ${testUrl}`);
        
        const response = await axios.get(testUrl, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        res.json({
            success: true,
            message: 'SCIM access working',
            totalUsers: response.data.totalResults,
            scimEndpoint: SCIM_BASE_URL,
            tokenEndpoint: TOKEN_URL
        });
        
    } catch (error) {
        console.error('❌ SCIM test failed:', error.response?.data);
        res.status(error.response?.status || 500).json({
            success: false,
            error: 'SCIM test failed',
            details: error.response?.data,
            status: error.response?.status,
            scimEndpoint: SCIM_BASE_URL,
            tokenEndpoint: TOKEN_URL
        });
    }
});

// Detailed diagnostic endpoint
app.get('/debug-users', async (req, res) => {
    try {
        console.log('🔍 Running detailed user diagnostics...');
        const accessToken = await getAccessToken();
        
        // Get all users with full details
        const allUsersUrl = `${SCIM_BASE_URL}?count=100`;
        console.log(`Fetching all users from: ${allUsersUrl}`);
        
        const response = await axios.get(allUsersUrl, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        const users = response.data.Resources || [];
        const userList = users.map(user => ({
            id: user.id,
            userName: user.userName,
            name: user.name,
            emails: user.emails,
            active: user.active,
            created: user.meta?.created,
            lastModified: user.meta?.lastModified
        }));
        
        res.json({
            success: true,
            totalFromAPI: response.data.totalResults,
            actualReturned: users.length,
            users: userList,
            searchedEmail: 'mishradarshan22@gmail.com',
            foundTarget: users.find(u => u.userName === 'mishradarshan22@gmail.com') || null,
            scimEndpoint: SCIM_BASE_URL
        });
        
    } catch (error) {
        console.error('❌ Debug failed:', error.response?.data);
        res.status(error.response?.status || 500).json({
            error: 'Debug failed',
            details: error.response?.data,
            status: error.response?.status
        });
    }
});

// List all users (for debugging)
app.get('/list-all-users', async (req, res) => {
    try {
        console.log('📋 Listing all users...');
        const accessToken = await getAccessToken();
        
        const response = await axios.get(`${SCIM_BASE_URL}?count=50`, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        const users = response.data.Resources.map(user => ({
            id: user.id,
            userName: user.userName,
            name: user.name,
            emails: user.emails,
            active: user.active,
            created: user.meta?.created
        }));
        
        res.json({
            totalUsers: response.data.totalResults,
            users: users
        });
        
    } catch (error) {
        console.error('❌ Failed to list users:', error.response?.data);
        res.status(error.response?.status || 500).json({
            error: 'Failed to list users',
            details: error.response?.data
        });
    }
});

// Test user creation endpoint
app.post('/test-create-user', async (req, res) => {
    try {
        console.log('🧪 Testing user creation...');
        const accessToken = await getAccessToken();
        
        const testUser = {
            userName: 'test.user@example.com',
            name: {
                givenName: 'Test',
                familyName: 'User',
            },
            emails: [{ primary: true, value: 'test.user@example.com', type: 'work' }],
            active: true
        };
        
        console.log('📋 Creating test user:', testUser);
        
        const createResponse = await axios.post(SCIM_BASE_URL, testUser, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
        });
        
        console.log('✅ User creation response:', createResponse.status, createResponse.data);
        
        // Immediately check if user exists
        const searchUrl = `${SCIM_BASE_URL}?filter=userName eq \"test.user@example.com\"`;
        const searchResponse = await axios.get(searchUrl, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        res.json({
            success: true,
            created: true,
            createResponse: {
                status: createResponse.status,
                data: createResponse.data
            },
            verification: {
                found: searchResponse.data.totalResults > 0,
                searchResults: searchResponse.data.totalResults,
                userData: searchResponse.data.Resources?.[0] || null
            }
        });
        
    } catch (error) {
        console.error('❌ Test user creation failed:', error.response?.data);
        res.status(error.response?.status || 500).json({
            success: false,
            error: 'Test creation failed',
            details: error.response?.data,
            status: error.response?.status
        });
    }
});

// 2. Webhook endpoint for Frappe HR events
app.post('/webhook-receiver', async (req, res) => {
    const eventType = req.header('x-frappe-event-type');
    const body = req.body;
    
    // Log incoming request for debugging
    console.log('📨 Incoming webhook:');
    console.log('Headers:', req.headers);
    console.log('Body:', body);
    console.log('Content-Type:', req.header('content-type'));
    
    if (!eventType) {
        return res.status(400).json({ error: 'Missing x-frappe-event-type header' });
    }
    
    // Enhanced validation for user_id
    if (!body || !body.user_id || body.user_id === 'None' || body.user_id === null || body.user_id === '') {
        console.error('❌ Invalid user_id:', body?.user_id);
        return res.status(400).json({ 
            error: 'Invalid or missing user_id in request body',
            received: body?.user_id,
            suggestion: 'Ensure the Employee record has a valid email address linked'
        });
    }
    
    const userEmail = body.user_id;
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(userEmail)) {
        console.error('❌ Invalid email format:', userEmail);
        return res.status(400).json({ 
            error: 'Invalid email format for user_id',
            received: userEmail,
            suggestion: 'user_id must be a valid email address'
        });
    }
    try {
        const accessToken = await getAccessToken();
        
        // Test SCIM endpoint access first
        console.log(`🔍 Testing SCIM endpoint access...`);
        try {
            const testResponse = await axios.get(`${SCIM_BASE_URL}?count=1`, {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });
            console.log(`✅ SCIM endpoint accessible, total users: ${testResponse.data.totalResults}`);
        } catch (testError) {
            console.error(`❌ SCIM endpoint test failed:`, testError.response?.status, testError.response?.data);
            if (testError.response?.status === 403) {
                return res.status(403).json({ 
                    error: 'SCIM API access denied',
                    message: 'The application does not have permission to access SCIM endpoints.',
                    suggestion: 'Please ensure SCIM2 Users API is properly authorized in Asgardeo Console'
                });
            }
        }
        
        // Search for user in Asgardeo SCIM
        const searchUrl = `${SCIM_BASE_URL}?filter=userName eq \"${userEmail}\"`;
        console.log(`🔍 Searching for user: ${userEmail}`);
        
        const searchResp = await axios.get(searchUrl, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        console.log(`📊 Search result: ${searchResp.data.totalResults} users found`);
        const userExists = searchResp.data.totalResults > 0;
        const userId = userExists ? searchResp.data.Resources[0].id : null;

        if (eventType === 'on_update') {
            // Map Frappe HR fields to SCIM 2.0
            const scimUser = {
                userName: body.user_id,
                name: {
                    givenName: body.first_name || '',
                    familyName: body.last_name || '',
                },
                emails: [{ primary: true, value: body.user_id, type: 'work' }],
                active: body.status === 'Active',
            };
            if (!userExists) {
                // Create user
                try {
                    console.log(`➕ Creating new user: ${userEmail}`);
                    await axios.post(SCIM_BASE_URL, scimUser, {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`,
                            'Content-Type': 'application/json',
                        },
                    });
                    console.log(`✅ User created successfully: ${userEmail}`);
                    return res.status(201).json({ message: 'User created' });
                } catch (err) {
                    console.error('❌ Error creating user:');
                    console.error('Status:', err.response?.status);
                    console.error('Status Text:', err.response?.statusText);
                    console.error('Response:', err.response?.data);
                    
                    if (err.response?.status === 403) {
                        return res.status(403).json({ 
                            error: 'SCIM permission denied. Please check application API permissions in Asgardeo Console.',
                            details: 'Ensure SCIM 2.0 Users API is authorized for your application.'
                        });
                    }
                    
                    return res.status(500).json({ error: 'Failed to create user', details: err.response?.data });
                }
            } else {
                // Update user via SCIM PATCH
                const patchBody = {
                    schemas: [
                        'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                    ],
                    Operations: [
                        { op: 'replace', path: 'name.givenName', value: scimUser.name.givenName },
                        { op: 'replace', path: 'name.familyName', value: scimUser.name.familyName },
                        { op: 'replace', path: 'emails', value: scimUser.emails },
                        { op: 'replace', path: 'active', value: scimUser.active },
                    ]
                };
                try {
                    await axios.patch(`${SCIM_BASE_URL}/${userId}`, patchBody, {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`,
                            'Content-Type': 'application/json',
                        },
                    });
                    console.log(`User updated: ${userEmail}`);
                    return res.status(200).json({ message: 'User updated' });
                } catch (err) {
                    console.error('Error updating user:', err.response?.data || err.message);
                    return res.status(500).json({ error: 'Failed to update user' });
                }
            }
        } else if (eventType === 'on_trash') {
            // Delete user if exists
            if (!userExists) {
                return res.status(404).json({ error: 'User not found' });
            }
            try {
                await axios.delete(`${SCIM_BASE_URL}/${userId}`, {
                    headers: { 'Authorization': `Bearer ${accessToken}` }
                });
                console.log(`User deleted: ${userEmail}`);
                return res.status(200).json({ message: 'User deleted' });
            } catch (err) {
                console.error('Error deleting user:', err.response?.data || err.message);
                return res.status(500).json({ error: 'Failed to delete user' });
            }
        } else {
            return res.status(400).json({ error: 'Unknown event type' });
        }
    } catch (error) {
        console.error('Webhook error:', error.response?.data || error.message);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Start the Express server
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
