// server.js
// Node.js Express server for integrating Frappe HR with WSO2 Asgardeo SCIM provisioning

require('dotenv').config();
const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

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
        return response.data.access_token;
    } catch (error) {
        console.error('Error fetching Asgardeo access token:', error.response?.data || error.message);
        throw error;
    }
}

// 2. Webhook endpoint for Frappe HR events
app.post('/webhook-receiver', async (req, res) => {
    const eventType = req.header('x-frappe-event-type');
    const body = req.body;
    if (!eventType) {
        return res.status(400).json({ error: 'Missing x-frappe-event-type header' });
    }
    if (!body || !body.user_id) {
        return res.status(400).json({ error: 'Missing user_id in request body' });
    }
    const userEmail = body.user_id;
    try {
        const accessToken = await getAccessToken();
        // Search for user in Asgardeo SCIM
        const searchUrl = `${SCIM_BASE_URL}?filter=userName eq \"${userEmail}\"`;
        const searchResp = await axios.get(searchUrl, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
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
                    await axios.post(SCIM_BASE_URL, scimUser, {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`,
                            'Content-Type': 'application/json',
                        },
                    });
                    console.log(`User created: ${userEmail}`);
                    return res.status(201).json({ message: 'User created' });
                } catch (err) {
                    console.error('Error creating user:', err.response?.data || err.message);
                    return res.status(500).json({ error: 'Failed to create user' });
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
