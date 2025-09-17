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
    
    // Enhanced validation and email extraction
    let userEmail = null;
    
    // Try multiple fields for email address
    if (body.user_id && body.user_id !== 'None' && body.user_id !== null && body.user_id !== '') {
        userEmail = body.user_id;
    } else if (body.company_email && body.company_email !== 'None') {
        userEmail = body.company_email;
    } else if (body.personal_email && body.personal_email !== 'None') {
        userEmail = body.personal_email;
    } else if (body.email && body.email !== 'None') {
        userEmail = body.email;
    }
    
    if (!userEmail) {
        console.error('❌ No valid email found in webhook data:', {
            user_id: body?.user_id,
            company_email: body?.company_email,
            personal_email: body?.personal_email,
            email: body?.email
        });
        return res.status(400).json({ 
            error: 'No valid email address found in webhook data',
            receivedFields: Object.keys(body || {}),
            suggestion: 'Ensure Employee record has email in user_id, company_email, or personal_email field'
        });
    }
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(userEmail)) {
        console.error('❌ Invalid email format:', userEmail);
        return res.status(400).json({ 
            error: 'Invalid email format',
            received: userEmail,
            suggestion: 'Email must be in valid format (user@domain.com)'
        });
    }
    
    console.log('✅ Using email:', userEmail);
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
            // Map Frappe HR fields to SCIM 2.0 - Asgardeo specific format
            const scimUser = {
                schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
                userName: userEmail,
                name: {
                    givenName: body.first_name ? body.first_name.trim() : '',
                    familyName: body.last_name ? body.last_name.trim() : '',
                    formatted: `${body.first_name ? body.first_name.trim() : ''} ${body.last_name ? body.last_name.trim() : ''}`.trim()
                },
                emails: [{ 
                    primary: true, 
                    value: userEmail, 
                    type: 'work' 
                }],
                active: body.status === 'Active'
                // Note: Password removed - Asgardeo likely doesn't allow password via SCIM
                // Note: Groups removed - might be causing validation issues
            };
            if (!userExists) {
                // Create user
                try {
                    console.log(`➕ Creating new user: ${userEmail}`);
                    console.log('📋 SCIM User data being sent:', JSON.stringify(scimUser, null, 2));
                    
                    const createResponse = await axios.post(SCIM_BASE_URL, scimUser, {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`,
                            'Content-Type': 'application/json',
                        },
                    });
                    
                    console.log('✅ SCIM Create Response Status:', createResponse.status);
                    console.log('✅ SCIM Create Response Data:', JSON.stringify(createResponse.data, null, 2));
                    
                    // Handle different response codes
                    if (createResponse.status === 202) {
                        console.log('⚠️ Status 202: Request accepted but processing asynchronously');
                        console.log('💡 This usually means validation failed or async processing');
                        
                        // Wait a moment and try verification multiple times
                        for (let attempt = 1; attempt <= 3; attempt++) {
                            console.log(`🔍 Verification attempt ${attempt}/3...`);
                            await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
                            
                            const verifyUrl = `${SCIM_BASE_URL}?filter=userName eq \"${userEmail}\"`;
                            const verifyResponse = await axios.get(verifyUrl, {
                                headers: { 'Authorization': `Bearer ${accessToken}` }
                            });
                            
                            console.log(`📊 Verification attempt ${attempt}: ${verifyResponse.data.totalResults} users found`);
                            
                            if (verifyResponse.data.totalResults > 0) {
                                console.log('✅ User verified in SCIM after delay:', verifyResponse.data.Resources[0].id);
                                return res.status(201).json({ 
                                    message: 'User created (verified after delay)',
                                    scimId: verifyResponse.data.Resources[0].id,
                                    verified: true,
                                    attempts: attempt
                                });
                            }
                        }
                        
                        // If still not found after 3 attempts
                        console.error('❌ User still not found after 3 verification attempts');
                        return res.status(202).json({ 
                            message: 'User creation queued but not yet processed',
                            status: 'pending',
                            suggestion: 'Check Asgardeo Console manually - user might appear later'
                        });
                    }
                    
                    // Immediately verify the user was actually created for non-202 responses
                    console.log('🔍 Verifying user creation...');
                    const verifyUrl = `${SCIM_BASE_URL}?filter=userName eq \"${userEmail}\"`;
                    const verifyResponse = await axios.get(verifyUrl, {
                        headers: { 'Authorization': `Bearer ${accessToken}` }
                    });
                    
                    console.log('📊 Verification result:', verifyResponse.data.totalResults, 'users found');
                    if (verifyResponse.data.totalResults > 0) {
                        console.log('✅ User verified in SCIM:', verifyResponse.data.Resources[0].id);
                    } else {
                        console.error('❌ User NOT found after creation!');
                    }
                    
                    console.log(`✅ User created successfully: ${userEmail}`);
                    return res.status(201).json({ 
                        message: 'User created',
                        scimId: createResponse.data.id,
                        verified: verifyResponse.data.totalResults > 0
                    });
                } catch (err) {
                    console.error('❌ Error creating user:');
                    console.error('Status:', err.response?.status);
                    console.error('Status Text:', err.response?.statusText);
                    console.error('Response:', JSON.stringify(err.response?.data, null, 2));
                    console.error('Full Error:', err.message);
                    
                    if (err.response?.status === 403) {
                        return res.status(403).json({ 
                            error: 'SCIM permission denied. Please check application API permissions in Asgardeo Console.',
                            details: 'Ensure SCIM 2.0 Users API is authorized for your application.'
                        });
                    }
                    
                    return res.status(500).json({ 
                        error: 'Failed to create user', 
                        details: err.response?.data,
                        scimUserData: scimUser
                    });
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
