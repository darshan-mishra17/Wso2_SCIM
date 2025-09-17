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

// Test Offline User Onboard API (correct approach according to Asgardeo docs)
app.post('/test-invite-user', async (req, res) => {
    try {
        console.log('🧪 Testing Offline User Onboard (Invite) API...');
        const accessToken = await getAccessToken();
        
        // Use the proper Offline User Onboard API
        const inviteApiUrl = `https://api.asgardeo.io/t/${ASGARDEO_TENANT}/api/identity/user/v1.0/invite`;
        
        const inviteData = {
            user: {
                username: 'test-invite@example.com',
                realm: 'DEFAULT'
            },
            properties: [
                {
                    key: 'givenName',
                    value: 'Test'
                },
                {
                    key: 'familyName', 
                    value: 'Invite'
                },
                {
                    key: 'email',
                    value: 'test-invite@example.com'
                }
            ]
        };
        
        console.log('📋 Invite API request:', JSON.stringify(inviteData, null, 2));
        
        const inviteResponse = await axios.post(inviteApiUrl, inviteData, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
        });
        
        console.log('✅ Invite API Response Status:', inviteResponse.status);
        console.log('✅ Invite API Response Data:', JSON.stringify(inviteResponse.data, null, 2));
        
        res.json({
            success: true,
            method: 'Offline User Onboard (Invite) API',
            response: inviteResponse.data,
            status: inviteResponse.status,
            message: 'User invitation sent successfully. User will receive email to complete registration.'
        });
        
    } catch (error) {
        console.error('❌ Invite API test failed:', error.response?.data);
        res.status(error.response?.status || 500).json({
            success: false,
            error: 'Invite API test failed',
            details: error.response?.data,
            status: error.response?.status
        });
    }
});

// Test SCIM user creation with password (required by Asgardeo)
app.post('/test-scim-create', async (req, res) => {
    try {
        console.log('🧪 Testing SCIM user creation with password...');
        const accessToken = await getAccessToken();
        
        const testUser = {
            schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
            userName: 'test-scim-password@example.com',
            password: 'TempPass123!@#', // Required by Asgardeo
            name: {
                givenName: 'Test',
                familyName: 'SCIM',
                formatted: 'Test SCIM'
            },
            emails: [{ 
                primary: true, 
                value: 'test-scim-password@example.com', 
                type: 'work' 
            }],
            active: true
        };
        
        console.log('📋 SCIM User data with password:', JSON.stringify(testUser, null, 2));
        
        const createResponse = await axios.post(SCIM_BASE_URL, testUser, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
        });
        
        console.log('✅ SCIM Create Response Status:', createResponse.status);
        console.log('✅ SCIM Create Response Data:', JSON.stringify(createResponse.data, null, 2));
        
        res.json({
            success: true,
            method: 'SCIM with password',
            response: createResponse.data,
            status: createResponse.status,
            message: 'User created successfully with temporary password'
        });
        
    } catch (error) {
        console.error('❌ SCIM create test failed:', error.response?.data);
        res.status(error.response?.status || 500).json({
            success: false,
            error: 'SCIM create test failed',
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
            if (!userExists) {
                // Use Offline User Onboard API (Invite) instead of direct SCIM creation
                try {
                    console.log(`➕ Inviting new user via Offline Onboard API: ${userEmail}`);
                    
                    const inviteApiUrl = `https://api.asgardeo.io/t/${ASGARDEO_TENANT}/api/identity/user/v1.0/invite`;
                    
                    const inviteData = {
                        user: {
                            username: userEmail,
                            realm: 'DEFAULT'
                        },
                        properties: [
                            {
                                key: 'givenName',
                                value: body.first_name ? body.first_name.trim() : ''
                            },
                            {
                                key: 'familyName', 
                                value: body.last_name ? body.last_name.trim() : ''
                            },
                            {
                                key: 'email',
                                value: userEmail
                            }
                        ]
                    };
                    
                    console.log('📋 Invite API request:', JSON.stringify(inviteData, null, 2));
                    
                    const inviteResponse = await axios.post(inviteApiUrl, inviteData, {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`,
                            'Content-Type': 'application/json',
                        },
                    });
                    
                    console.log('✅ Invite API Response Status:', inviteResponse.status);
                    console.log('✅ Invite API Response Data:', JSON.stringify(inviteResponse.data, null, 2));
                    
                    console.log(`✅ User invitation sent successfully: ${userEmail}`);
                    return res.status(201).json({ 
                        message: 'User invitation sent successfully',
                        method: 'Offline User Onboard (Invite)',
                        email: userEmail,
                        note: 'User will receive email invitation to complete registration'
                    });
                    
                } catch (createError) {
                    console.error('❌ User invite failed:', createError.response?.data);
                    
                    // If invite fails, try the old SCIM method as backup
                    console.log('🔄 Falling back to SCIM creation...');
                    
                    try {
                        const scimUserFallback = {
                            schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
                            userName: userEmail,
                            password: "TempPass123!@#", // Required by Asgardeo - user will change via invite
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
                        };
                        
                        console.log('📋 SCIM User data being sent:', JSON.stringify(scimUserFallback, null, 2));
                        
                        const createResponse = await axios.post(SCIM_BASE_URL, scimUserFallback, {
                            headers: {
                                'Authorization': `Bearer ${accessToken}`,
                                'Content-Type': 'application/json',
                            },
                        });
                        
                        console.log('✅ SCIM Create Response Status:', createResponse.status);
                        console.log('✅ SCIM Create Response Data:', JSON.stringify(createResponse.data, null, 2));
                        
                        return res.status(202).json({ 
                            message: 'User creation attempted with SCIM (fallback)',
                            primary_method_failed: 'Invite API',
                            fallback_used: 'SCIM API',
                            status: createResponse.status,
                            note: 'Check Asgardeo Console for user status'
                        });
                    } catch (scimError) {
                        console.error('❌ Error in fallback SCIM creation:', scimError.response?.data);
                        return res.status(500).json({ 
                            error: 'Both Invite API and SCIM creation failed', 
                            inviteError: createError.response?.data,
                            scimError: scimError.response?.data
                        });
                    }
                }
            } else {
                // Update user via SCIM PATCH
                const patchBody = {
                    schemas: [
                        'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                    ],
                    Operations: [
                        { op: 'replace', path: 'name.givenName', value: body.first_name ? body.first_name.trim() : '' },
                        { op: 'replace', path: 'name.familyName', value: body.last_name ? body.last_name.trim() : '' },
                        { op: 'replace', path: 'emails', value: [{ primary: true, value: userEmail, type: 'work' }] },
                        { op: 'replace', path: 'active', value: body.status === 'Active' },
                    ]
                };
                try {
                    await axios.patch(`${SCIM_BASE_URL}/${userId}`, patchBody, {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`,
                            'Content-Type': 'application/json',
                        },
                    });
                    console.log(`✅ User updated: ${userEmail}`);
                    return res.status(200).json({ message: 'User updated' });
                } catch (err) {
                    console.error('❌ Error updating user:', err.response?.data || err.message);
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
                console.log(`✅ User deleted: ${userEmail}`);
                return res.status(200).json({ message: 'User deleted' });
            } catch (err) {
                console.error('❌ Error deleting user:', err.response?.data || err.message);
                return res.status(500).json({ error: 'Failed to delete user' });
            }
        } else {
            return res.status(400).json({ error: 'Unknown event type' });
        }
    } catch (error) {
        console.error('❌ Webhook error:', error.response?.data || error.message);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Start the Express server
app.listen(PORT, () => {
    console.log(`🚀 Server listening on port ${PORT}`);
});