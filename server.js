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

// Comprehensive SCIM2 user creation function that handles various tenant configurations
async function createUserViaSCIM2(userDetails, options = {}) {
    const {
        email,
        firstName = '',
        lastName = '',
        password = 'TempPass123!@#',
        active = true,
        maxRetries = 3,
        retryDelay = 2000
    } = userDetails;
    
    const {
        waitForCreation = true,
        checkMultipleTimes = true
    } = options;
    
    console.log(`🚀 Starting comprehensive SCIM2 user creation for: ${email}`);
    
    try {
        const accessToken = await getAccessToken();
        
        // Enhanced SCIM2 user payload with all possible schemas and configurations
        const scimUser = {
            schemas: [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
            ],
            userName: email,
            password: password,
            name: {
                givenName: firstName,
                familyName: lastName,
                formatted: `${firstName} ${lastName}`.trim()
            },
            emails: [{ 
                primary: true, 
                value: email, 
                type: 'work' 
            }],
            active: active,
            // Enterprise schema with comprehensive settings
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "askPassword": false,      // Don't force password reset
                "verifyEmail": false,      // Don't require email verification
                "accountLocked": false     // Don't lock account
            }
        };
        
        console.log('📋 Creating user with comprehensive SCIM2 payload...');
        
        // Create the user
        const createResponse = await axios.post(SCIM_BASE_URL, scimUser, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
        });
        
        console.log(`✅ SCIM2 Create Response Status: ${createResponse.status}`);
        console.log(`📄 SCIM2 Response Data:`, createResponse.data ? JSON.stringify(createResponse.data, null, 2) : 'Empty response');
        
        if (!waitForCreation) {
            return {
                success: true,
                status: createResponse.status,
                message: 'User creation request submitted',
                response: createResponse.data
            };
        }
        
        // Verification with retry logic for different tenant configurations
        console.log('🔍 Starting user verification with retry logic...');
        
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            console.log(`🔄 Verification attempt ${attempt}/${maxRetries}`);
            
            try {
                const verifyResponse = await axios.get(`${SCIM_BASE_URL}?filter=userName eq "${email}"`, {
                    headers: { 'Authorization': `Bearer ${accessToken}` }
                });
                
                const userExists = verifyResponse.data.totalResults > 0;
                const userData = userExists ? verifyResponse.data.Resources[0] : null;
                
                if (userExists) {
                    console.log('🎉 User successfully created and verified!');
                    console.log('👤 User details:', JSON.stringify(userData, null, 2));
                    
                    return {
                        success: true,
                        status: createResponse.status,
                        message: 'User created and verified successfully',
                        user: userData,
                        createResponse: createResponse.data,
                        verification: {
                            attempts: attempt,
                            found: true
                        }
                    };
                }
                
                console.log(`⏳ User not found yet (attempt ${attempt}). Waiting ${retryDelay}ms before retry...`);
                
                if (attempt < maxRetries) {
                    await new Promise(resolve => setTimeout(resolve, retryDelay));
                }
                
            } catch (verifyError) {
                console.error(`❌ Verification attempt ${attempt} failed:`, verifyError.response?.data);
                if (attempt === maxRetries) {
                    throw verifyError;
                }
            }
        }
        
        // If we get here, user wasn't found after all retries
        console.log('⚠️ User creation accepted but user not found after all verification attempts');
        
        return {
            success: false,
            status: createResponse.status,
            message: `User creation accepted (${createResponse.status}) but user not found after ${maxRetries} verification attempts`,
            createResponse: createResponse.data,
            verification: {
                attempts: maxRetries,
                found: false,
                possibleCauses: [
                    'Tenant has "Lock account until password is set" enabled',
                    'Email verification required before user becomes active',
                    'Admin approval required for new users',
                    'Domain restrictions preventing user creation'
                ]
            }
        };
        
    } catch (error) {
        console.error('❌ SCIM2 user creation failed:', error.response?.data || error.message);
        
        return {
            success: false,
            error: 'SCIM2 user creation failed',
            details: error.response?.data || error.message,
            status: error.response?.status,
            troubleshooting: {
                '401': 'Authentication failed - check client credentials',
                '403': 'Permission denied - ensure SCIM2 Users API access is granted',
                '409': 'User already exists with this email',
                '422': 'Validation failed - check required fields and password policy'
            }[error.response?.status] || 'Unknown error occurred'
        };
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

// Test comprehensive SCIM2 user creation with retry logic
app.post('/test-comprehensive-scim', async (req, res) => {
    try {
        console.log('🧪 Testing comprehensive SCIM2 user creation with retry logic...');
        
        const testUserDetails = {
            email: 'comprehensive-test@example.com',
            firstName: 'Comprehensive',
            lastName: 'Test',
            password: 'TempPass123!@#',
            active: true
        };
        
        const options = {
            waitForCreation: true,
            checkMultipleTimes: true
        };
        
        const result = await createUserViaSCIM2(testUserDetails, options);
        
        res.json({
            testType: 'Comprehensive SCIM2 Creation with Retry Logic',
            timestamp: new Date().toISOString(),
            ...result
        });
        
    } catch (error) {
        console.error('❌ Comprehensive SCIM2 test failed:', error);
        res.status(500).json({
            testType: 'Comprehensive SCIM2 Creation',
            success: false,
            error: 'Test failed',
            details: error.message
        });
    }
});

// Test SCIM user creation with comprehensive payload for Asgardeo
app.post('/test-scim-create', async (req, res) => {
    try {
        console.log('🧪 Testing comprehensive SCIM2 user creation...');
        const accessToken = await getAccessToken();
        
        const testUser = {
            schemas: [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
            ],
            userName: 'test-comprehensive-scim@example.com',
            password: 'TempPass123!@#', // Required by Asgardeo
            name: {
                givenName: 'Test',
                familyName: 'Comprehensive',
                formatted: 'Test Comprehensive'
            },
            emails: [{ 
                primary: true, 
                value: 'test-comprehensive-scim@example.com', 
                type: 'work' 
            }],
            active: true,
            // Comprehensive enterprise schema for Asgardeo compatibility
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "askPassword": false,           // Don't require password change on first login
                "verifyEmail": false,          // Don't require email verification
                "accountLocked": false,        // Ensure account is not locked
                "accountDisabled": false,      // Ensure account is enabled
                "passwordResetRequired": false // Don't force password reset
            }
        };
        
        console.log('📋 Comprehensive SCIM2 User data:', JSON.stringify(testUser, null, 2));
        
        const createResponse = await axios.post(SCIM_BASE_URL, testUser, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
        });
        
        console.log('✅ SCIM2 Create Response Status:', createResponse.status);
        console.log('✅ SCIM2 Create Response Data:', JSON.stringify(createResponse.data, null, 2));
        
        // Wait a moment for potential async processing
        console.log('⏳ Waiting 2 seconds for user processing...');
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Comprehensive verification with multiple search methods
        console.log('🔍 Performing comprehensive user verification...');
        
        // Method 1: Search by userName
        const verifyByUserName = await axios.get(`${SCIM_BASE_URL}?filter=userName eq "${testUser.userName}"`, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        // Method 2: Search by email
        const verifyByEmail = await axios.get(`${SCIM_BASE_URL}?filter=emails.value eq "${testUser.emails[0].value}"`, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        // Method 3: If we got an ID from creation, try to fetch directly
        let verifyById = null;
        if (createResponse.data && createResponse.data.id) {
            try {
                verifyById = await axios.get(`${SCIM_BASE_URL}/${createResponse.data.id}`, {
                    headers: { 'Authorization': `Bearer ${accessToken}` }
                });
            } catch (idError) {
                console.log('⚠️ Direct ID lookup failed:', idError.response?.status);
            }
        }
        
        const userExistsByUserName = verifyByUserName.data.totalResults > 0;
        const userExistsByEmail = verifyByEmail.data.totalResults > 0;
        const userExistsById = verifyById !== null;
        
        console.log(`📊 Verification Results:`);
        console.log(`   - By userName: ${userExistsByUserName ? 'FOUND' : 'NOT FOUND'}`);
        console.log(`   - By email: ${userExistsByEmail ? 'FOUND' : 'NOT FOUND'}`);
        console.log(`   - By ID: ${userExistsById ? 'FOUND' : 'NOT FOUND'}`);
        
        const userExists = userExistsByUserName || userExistsByEmail || userExistsById;
        const userData = userExistsByUserName ? verifyByUserName.data.Resources[0] : 
                        userExistsByEmail ? verifyByEmail.data.Resources[0] : 
                        userExistsById ? verifyById.data : null;
        
        res.json({
            success: true,
            method: 'Comprehensive SCIM2 with enterprise schema',
            createResponse: createResponse.data,
            status: createResponse.status,
            verification: {
                userExists: userExists,
                methods: {
                    byUserName: { found: userExistsByUserName, results: verifyByUserName.data.totalResults },
                    byEmail: { found: userExistsByEmail, results: verifyByEmail.data.totalResults },
                    byId: { found: userExistsById, available: createResponse.data?.id !== undefined }
                },
                userData: userData
            },
            message: userExists ? 'User created and verified successfully!' : 'User creation accepted but not found in any search method'
        });
        
    } catch (error) {
        console.error('❌ Comprehensive SCIM2 create test failed:', error.response?.data);
        res.status(error.response?.status || 500).json({
            success: false,
            error: 'Comprehensive SCIM2 create test failed',
            details: error.response?.data,
            status: error.response?.status
        });
    }
});

// Check if a specific user exists in Asgardeo
app.get('/check-user/:email', async (req, res) => {
    try {
        const userEmail = req.params.email;
        console.log(`🔍 Checking if user exists: ${userEmail}`);
        
        const accessToken = await getAccessToken();
        const searchUrl = `${SCIM_BASE_URL}?filter=userName eq \"${userEmail}\"`;
        
        const searchResponse = await axios.get(searchUrl, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        const userExists = searchResponse.data.totalResults > 0;
        const userData = userExists ? searchResponse.data.Resources[0] : null;
        
        console.log(`📊 User check result: ${userExists ? 'FOUND' : 'NOT FOUND'}`);
        
        res.json({
            email: userEmail,
            exists: userExists,
            totalResults: searchResponse.data.totalResults,
            user: userData,
            searchUrl: searchUrl
        });
        
    } catch (error) {
        console.error('❌ User check failed:', error.response?.data);
        res.status(error.response?.status || 500).json({
            error: 'User check failed',
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
                    
                    // If invite fails, use comprehensive SCIM2 creation as backup
                    console.log('🔄 Falling back to comprehensive SCIM2 creation...');
                    
                    const userDetails = {
                        email: userEmail,
                        firstName: body.first_name ? body.first_name.trim() : '',
                        lastName: body.last_name ? body.last_name.trim() : '',
                        password: 'TempPass123!@#',
                        active: body.status === 'Active'
                    };
                    
                    const options = {
                        waitForCreation: true,
                        checkMultipleTimes: true
                    };
                    
                    const scimResult = await createUserViaSCIM2(userDetails, options);
                    
                    if (scimResult.success) {
                        return res.status(201).json({
                            message: `User ${userEmail} created successfully via comprehensive SCIM2`,
                            method: 'Comprehensive SCIM2 (fallback from Invite API)',
                            user: scimResult.user,
                            verification: scimResult.verification
                        });
                    } else {
                        return res.status(202).json({
                            message: `User creation request processed but verification failed`,
                            method: 'Comprehensive SCIM2 (fallback from Invite API)',
                            details: scimResult.message,
                            possibleCauses: scimResult.verification?.possibleCauses || [],
                            troubleshooting: scimResult.troubleshooting
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