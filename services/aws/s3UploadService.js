const path = require("path");
const crypto = require("crypto");
const {
  PutObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
} = require("@aws-sdk/client-s3");
const { Upload } = require("@aws-sdk/lib-storage");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { createS3Client, getS3ConfigFromEnv } = require("./s3Client");

const DEFAULT_MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024; // 1 GB
const DEFAULT_ALLOWED_MIME_TYPES = [
  "video/mp4",
  "video/webm",
  "video/quicktime",
  "video/x-msvideo",
  "video/x-matroska",
  "image/jpeg",
  "image/png",
  "application/pdf",
  "text/plain",
];

class S3UploadError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {number} statusCode
   */
  constructor(code, message, statusCode = 500) {
    super(message);
    this.name = "S3UploadError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

let cached = null;

function getServiceConfig() {
  const cfg = getS3ConfigFromEnv();
  const maxFileSizeBytes = Number(process.env.S3_MAX_FILE_SIZE_BYTES || DEFAULT_MAX_FILE_SIZE_BYTES);
  const allowed = String(process.env.S3_ALLOWED_MIME_TYPES || "").trim();
  const allowedMimeTypes = allowed
    ? allowed.split(",").map((s) => s.trim()).filter(Boolean)
    : DEFAULT_ALLOWED_MIME_TYPES;

  return {
    ...cfg,
    maxFileSizeBytes,
    allowedMimeTypes,
    isPublicBucket: String(process.env.S3_PUBLIC_BUCKET || "false").toLowerCase() === "true",
    multipartThresholdBytes: Number(process.env.S3_MULTIPART_THRESHOLD_BYTES || 8 * 1024 * 1024),
  };
}

async function getService() {
  if (cached) return cached;

  const cfg = getServiceConfig();
  if (!cfg.credentials && (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY)) {
    throw new S3UploadError(
      "missing_aws_credentials",
      "AWS credentials are missing. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or attach an IAM role.",
      500
    );
  }

  const client = createS3Client();

  // Detect invalid bucket configuration early to fail fast.
  try {
    await client.send(new HeadBucketCommand({ Bucket: cfg.bucket }));
  } catch (err) {
    throw mapS3Error(err, "Invalid bucket configuration or inaccessible bucket");
  }

  cached = { client, cfg };
  return cached;
}

function clearServiceCache() {
  cached = null;
}

/**
 * @param {string} bucket
 * @param {string} region
 * @param {string} key
 */
function buildPublicObjectUrl(bucket, region, key) {
  const safeKey = String(key || "")
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
  return `https://${bucket}.s3.${region}.amazonaws.com/${safeKey}`;
}

/**
 * @param {{originalname?:string,mimetype?:string,size?:number,buffer?:Buffer}} file
 * @param {{maxFileSizeBytes:number,allowedMimeTypes:string[]}} cfg
 */
function validateFile(file, cfg) {
  if (!file) {
    throw new S3UploadError("missing_file", "No file was provided", 400);
  }

  if (!file.size || file.size <= 0) {
    throw new S3UploadError("empty_file", "Empty files are not allowed", 400);
  }

  if (file.size > cfg.maxFileSizeBytes) {
    throw new S3UploadError(
      "file_too_large",
      `File exceeds max size limit of ${cfg.maxFileSizeBytes} bytes`,
      400
    );
  }

  const mimeType = String(file.mimetype || "").toLowerCase();
  if (!cfg.allowedMimeTypes.includes(mimeType)) {
    throw new S3UploadError("invalid_file_type", `File type ${mimeType || "unknown"} is not allowed`, 400);
  }

  if (!Buffer.isBuffer(file.buffer)) {
    throw new S3UploadError("invalid_file_buffer", "File content buffer is missing", 400);
  }
}

function createObjectKey(fileName, keyPrefix) {
  const ext = path.extname(String(fileName || "")).toLowerCase();
  const randomPart = crypto.randomUUID();
  const prefix = String(keyPrefix || "").replace(/^\/+/, "").replace(/\/+$/, "");
  return prefix ? `${prefix}/${Date.now()}-${randomPart}${ext}` : `${Date.now()}-${randomPart}${ext}`;
}

/**
 * Upload one file to S3.
 * Uses multipart upload for large files through AWS SDK v3 Upload utility.
 * @param {{originalname:string,mimetype:string,size:number,buffer:Buffer}} file
 * @param {{keyPrefix?:string,key?:string}} options
 */
async function uploadFile(file, options = {}) {
  const { client, cfg } = await getService();
  validateFile(file, cfg);

  const key = options.key || createObjectKey(file.originalname, options.keyPrefix);

  try {
    let etag;
    if (file.size >= cfg.multipartThresholdBytes) {
      const uploader = new Upload({
        client,
        params: {
          Bucket: cfg.bucket,
          Key: key,
          Body: file.buffer,
          ContentType: file.mimetype,
        },
        queueSize: 4,
        partSize: 8 * 1024 * 1024,
        leavePartsOnError: false,
      });
      const result = await uploader.done();
      etag = result && result.ETag ? result.ETag : undefined;
    } else {
      const result = await client.send(
        new PutObjectCommand({
          Bucket: cfg.bucket,
          Key: key,
          Body: file.buffer,
          ContentType: file.mimetype,
        })
      );
      etag = result && result.ETag ? result.ETag : undefined;
    }

    const publicUrl = cfg.isPublicBucket ? buildPublicObjectUrl(cfg.bucket, cfg.region, key) : null;

    console.log("[s3-upload] success", { key, bucket: cfg.bucket, size: file.size });

    return {
      key,
      publicUrl,
      bucket: cfg.bucket,
      status: "uploaded",
      etag,
    };
  } catch (err) {
    const mapped = mapS3Error(err, "File upload failed");
    console.error("[s3-upload] failure", {
      code: mapped.code,
      message: mapped.message,
      fileName: file && file.originalname,
      bucket: cfg.bucket,
    });
    throw mapped;
  }
}

/**
 * Upload multiple files concurrently.
 * @param {Array<{originalname:string,mimetype:string,size:number,buffer:Buffer}>} files
 * @param {{keyPrefix?:string}} options
 */
async function uploadMultipleFiles(files, options = {}) {
  if (!Array.isArray(files) || files.length === 0) {
    throw new S3UploadError("missing_files", "No files were provided", 400);
  }

  const tasks = files.map(async (file) => {
    try {
      const result = await uploadFile(file, options);
      return { ...result, fileName: file.originalname };
    } catch (err) {
      return {
        key: null,
        publicUrl: null,
        bucket: String(process.env.AWS_S3_BUCKET || process.env.S3_BUCKET_NAME || ""),
        status: "failed",
        fileName: file && file.originalname,
        error: { code: err.code || "upload_failed", message: err.message || "Upload failed" },
      };
    }
  });

  return Promise.all(tasks);
}

/**
 * Delete an object from S3 bucket.
 * @param {string} key
 */
async function deleteFile(key) {
  if (!key) {
    throw new S3UploadError("missing_key", "Object key is required", 400);
  }

  const { client, cfg } = await getService();
  try {
    await client.send(new DeleteObjectCommand({ Bucket: cfg.bucket, Key: key.replace(/^\/+/, "") }));
    console.log("[s3-delete] success", { key, bucket: cfg.bucket });
    return {
      key,
      bucket: cfg.bucket,
      status: "deleted",
    };
  } catch (err) {
    const mapped = mapS3Error(err, "Delete failed");
    console.error("[s3-delete] failure", { code: mapped.code, message: mapped.message, key });
    throw mapped;
  }
}

/**
 * Generate presigned upload URL for direct browser-to-S3 uploads.
 * @param {string} key
 * @param {{expiresInSeconds?:number,contentType?:string}} options
 */
async function generatePresignedUploadUrl(key, options = {}) {
  if (!key) {
    throw new S3UploadError("missing_key", "Object key is required", 400);
  }

  const { client, cfg } = await getService();

  try {
    const command = new PutObjectCommand({
      Bucket: cfg.bucket,
      Key: key.replace(/^\/+/, ""),
      ContentType: options.contentType || "application/octet-stream",
    });

    const url = await getSignedUrl(client, command, {
      expiresIn: Number(options.expiresInSeconds || 900),
    });

    return {
      key: key.replace(/^\/+/, ""),
      bucket: cfg.bucket,
      status: "presigned",
      url,
    };
  } catch (err) {
    throw mapS3Error(err, "Failed to generate presigned upload URL");
  }
}

/**
 * Generate presigned download URL for secure object access.
 * @param {string} key
 * @param {{expiresInSeconds?:number}} options
 */
async function generatePresignedDownloadUrl(key, options = {}) {
  if (!key) {
    throw new S3UploadError("missing_key", "Object key is required", 400);
  }

  const { client, cfg } = await getService();

  try {
    const command = new GetObjectCommand({
      Bucket: cfg.bucket,
      Key: key.replace(/^\/+/, ""),
    });

    const url = await getSignedUrl(client, command, {
      expiresIn: Number(options.expiresInSeconds || 3600),
    });

    return {
      key: key.replace(/^\/+/, ""),
      bucket: cfg.bucket,
      status: "presigned",
      url,
    };
  } catch (err) {
    throw mapS3Error(err, "Failed to generate presigned download URL");
  }
}

function mapS3Error(err, fallbackMessage) {
  const code = (err && (err.name || err.Code || err.code)) || "s3_operation_failed";
  const message = (err && err.message) || fallbackMessage || "S3 operation failed";

  if (code === "CredentialsProviderError" || code === "InvalidAccessKeyId" || code === "SignatureDoesNotMatch") {
    return new S3UploadError("missing_aws_credentials", "AWS credentials are invalid or missing", 500);
  }

  if (code === "NoSuchBucket" || code === "NotFound" || code === "PermanentRedirect") {
    return new S3UploadError("invalid_bucket_configuration", message, 500);
  }

  if (code === "NetworkingError" || code === "TimeoutError" || code === "ECONNRESET" || code === "ENOTFOUND") {
    return new S3UploadError("network_error", message, 503);
  }

  return new S3UploadError("upload_failed", message, 500);
}

module.exports = {
  S3UploadError,
  uploadFile,
  uploadMultipleFiles,
  deleteFile,
  generatePresignedUploadUrl,
  generatePresignedDownloadUrl,
  clearServiceCache,
};
