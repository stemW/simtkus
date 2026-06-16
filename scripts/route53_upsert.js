const https = require('http');
const AWS = require('aws-sdk');
require('dotenv').config();

const { HOSTED_ZONE_ID, HOSTNAME, ROUTE53_TTL = '300', AWS_REGION } = process.env;

function log(...args){ console.log(new Date().toISOString(), ...args); }

if(!HOSTED_ZONE_ID){
  log('HOSTED_ZONE_ID missing in environment; aborting.');
  process.exit(2);
}
if(!HOSTNAME){
  log('HOSTNAME missing in environment; aborting.');
  process.exit(2);
}

function getPublicIPv4(){
  return new Promise((resolve, reject) => {
    const urls = ['https://ifconfig.me', 'https://ifconfig.co', 'https://api.ipify.org'];
    let tried = 0;
    function tryOne(){
      const url = urls[tried++] || urls[0];
      https.get(url, { timeout: 5000 }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          const ip = data.trim();
          if(/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return resolve(ip);
          if(tried < urls.length) return tryOne();
          reject(new Error('No IPv4 returned from services'));
        });
      }).on('error', (err) => {
        if(tried < urls.length) return tryOne();
        reject(err);
      });
    }
    tryOne();
  });
}

async function main(){
  log('Starting Route53 UPSERT script');
  log('HOSTED_ZONE_ID=', HOSTED_ZONE_ID, 'HOSTNAME=', HOSTNAME, 'AWS_REGION=', AWS_REGION || 'default');
  if(AWS_REGION) AWS.config.update({ region: AWS_REGION });

  const route53 = new AWS.Route53();

  try{
    const ip = await getPublicIPv4();
    log('Public IPv4 detected:', ip);

    // Build target record
    const fqdn = HOSTNAME.endsWith('.') ? HOSTNAME : HOSTNAME + '.';
    const params = {
      HostedZoneId: HOSTED_ZONE_ID,
      ChangeBatch: {
        Comment: 'Autosync from local host via route53_upsert.js',
        Changes: [{
          Action: 'UPSERT',
          ResourceRecordSet: {
            Name: fqdn,
            Type: 'A',
            TTL: parseInt(ROUTE53_TTL, 10) || 300,
            ResourceRecords: [{ Value: ip }]
          }
        }]
      }
    };

    log('Submitting UPSERT to Route53 for', fqdn);
    const res = await route53.changeResourceRecordSets(params).promise();
    log('Route53 change submitted:', JSON.stringify(res));
    if(res.ChangeInfo && res.ChangeInfo.Id) {
      log('Change ID:', res.ChangeInfo.Id, 'Status:', res.ChangeInfo.Status);
    }

    // List the record to confirm
    const list = await route53.listResourceRecordSets({ HostedZoneId: HOSTED_ZONE_ID, StartRecordName: fqdn, StartRecordType: 'A', MaxItems: '1' }).promise();
    log('Record list result:', JSON.stringify(list.ResourceRecordSets, null, 2));

    log('Done.');
    process.exit(0);
  }catch(err){
    console.error('ERROR:', err && err.stack ? err.stack : err);
    process.exit(3);
  }
}

main();
