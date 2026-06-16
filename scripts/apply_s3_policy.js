const fs = require('fs');
const path = require('path');
const AWS = require('aws-sdk');
require('dotenv').config();

function log(...args){ console.log(new Date().toISOString(), ...args); }

const BUCKET = process.env.S3_BUCKET_NAME || process.env.BUCKET || 'stemtk';
const POLICY_FILE = path.join(__dirname, '..', 'deploy', 'iam', 's3_policy.json');

if(!fs.existsSync(POLICY_FILE)){
  console.error('Policy file not found:', POLICY_FILE);
  process.exit(2);
}

let raw = fs.readFileSync(POLICY_FILE, 'utf8');
let policyJson;
try{ policyJson = JSON.parse(raw); }catch(e){ console.error('Invalid JSON in policy file:', e); process.exit(3); }

// Filter statements that reference the bucket name
const filteredStatements = (policyJson.Statement || []).filter(stmt => JSON.stringify(stmt).includes(BUCKET));
if(filteredStatements.length === 0){
  console.error('No statements referencing bucket', BUCKET, 'found in policy file. Aborting.');
  process.exit(4);
}

const policyToApply = {
  Version: policyJson.Version || '2012-10-17',
  Statement: filteredStatements
};

if(process.env.AWS_REGION) AWS.config.update({ region: process.env.AWS_REGION });
const s3 = new AWS.S3();

async function main(){
  try{
    log('Applying bucket policy to', BUCKET);
    const params = {
      Bucket: BUCKET,
      Policy: JSON.stringify(policyToApply)
    };
    const res = await s3.putBucketPolicy(params).promise();
    log('putBucketPolicy result:', JSON.stringify(res) || '(empty)');
    log('Success. Verify in S3 console or with AWS CLI: aws s3api get-bucket-policy --bucket', BUCKET);
    process.exit(0);
  }catch(err){
    console.error('ERROR:', err && err.stack ? err.stack : err);
    process.exit(5);
  }
}

main();
