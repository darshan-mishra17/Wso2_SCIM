// Simple local test script for the SCIM webhook
const http = require('http');

function post(path, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const json = JSON.stringify(data);
    const req = http.request({
      hostname: 'localhost',
      port: 3000,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(json),
        ...headers,
      }
    }, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body || '{}') }); }
        catch { resolve({ status: res.statusCode, body }); }
      });
    });
    req.on('error', reject);
    req.write(json);
    req.end();
  });
}

(async () => {
  const email = 'test.user.scim@example.com';
  console.log('--- CREATE / UPDATE (on_update) ---');
  let r1 = await post('/frappe-webhook', {
    first_name: 'Test',
    last_name: 'User',
    user_id: email,
    status: 'Active'
  }, { 'x-frappe-event-type': 'on_update' });
  console.log(r1);

  console.log('\n--- UPDATE again with new name ---');
  let r2 = await post('/frappe-webhook', {
    first_name: 'Tester',
    last_name: 'User',
    user_id: email,
    status: 'Active'
  }, { 'x-frappe-event-type': 'on_update' });
  console.log(r2);

  console.log('\n--- DELETE (on_trash) ---');
  let r3 = await post('/frappe-webhook', { user_id: email }, { 'x-frappe-event-type': 'on_trash' });
  console.log(r3);
})();
