const { S3Client } = require("@aws-sdk/client-s3");

/**
 * Resolve S3 runtime configuration from environment variables.
 * Supports AWS_S3_BUCKET as primary and S3_BUCKET_NAME for backward compatibility.
 * @returns {{region:string,bucket:string,credentials?:{accessKeyId:string,secretAccessKey:string}}}
 */
function getS3ConfigFromEnv() {
  const region = String(process.env.AWS_REGION || "").trim();
  const bucket = String(process.env.AWS_S3_BUCKET || process.env.S3_BUCKET_NAME || "").trim();
  const accessKeyId = String(process.env.AWS_ACCESS_KEY_ID || "").trim();
  const secretAccessKey = String(process.env.AWS_SECRET_ACCESS_KEY || "").trim();

  if (!region) {
    throw new Error("AWS_REGION is missing");
  }

  if (!bucket) {
    throw new Error("AWS_S3_BUCKET is missing");
  }

  const hasCredentials = Boolean(accessKeyId && secretAccessKey);
  return {
    region,
    bucket,
    credentials: hasCredentials ? { accessKeyId, secretAccessKey } : undefined,
  };
}

/**
 * Build a reusable S3 client.
 * Prefer IAM role credentials in production; env credentials are still supported.
 * @returns {S3Client}
 */
function createS3Client() {
  const cfg = getS3ConfigFromEnv();
  const clientConfig = {
    region: cfg.region,
    maxAttempts: 3,
  };

  if (cfg.credentials) {
    clientConfig.credentials = cfg.credentials;
  }

  return new S3Client(clientConfig);
}

module.exports = {
  createS3Client,
  getS3ConfigFromEnv,
};
