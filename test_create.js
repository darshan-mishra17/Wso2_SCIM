const http = require('http');

function post(path, data, headers={}) {
  return new Promise((resolve,reject)=>{
    const json = JSON.stringify(data);
    const req = http.request({host:'localhost',port:3000,path,method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(json),...headers}},res=>{
      let body='';
      res.on('data',c=>body+=c);
      res.on('end',()=>{try{resolve({status:res.statusCode,body:JSON.parse(body||'{}')});}catch{resolve({status:res.statusCode,body});}});
    });
    req.on('error',reject);
    req.write(json);req.end();
  });
}
(async()=>{
  const email='local.create.test@example.com';
  const resp=await post('/frappe-webhook',{first_name:'Local',last_name:'CreateTest',user_id:email,status:'Active'},{'x-frappe-event-type':'on_update'});
  console.log('Create response:',resp);
})();
