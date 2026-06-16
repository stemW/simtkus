export type UploadStatus = "uploaded" | "failed" | "deleted" | "presigned";

export interface UploadResult {
  key: string | null;
  publicUrl: string | null;
  bucket: string;
  status: UploadStatus;
  etag?: string;
  fileName?: string;
  error?: { code: string; message: string };
}

export interface UploadableFile {
  originalname: string;
  mimetype: string;
  size: number;
  buffer: Buffer;
}

export interface UploadOptions {
  keyPrefix?: string;
  key?: string;
}

export interface PresignOptions {
  expiresInSeconds?: number;
  contentType?: string;
}

export class S3UploadError extends Error {
  code: string;
  statusCode: number;
  constructor(code: string, message: string, statusCode?: number);
}

export function uploadFile(file: UploadableFile, options?: UploadOptions): Promise<UploadResult>;
export function uploadMultipleFiles(files: UploadableFile[], options?: UploadOptions): Promise<UploadResult[]>;
export function deleteFile(key: string): Promise<{ key: string; bucket: string; status: "deleted" }>;
export function generatePresignedUploadUrl(
  key: string,
  options?: PresignOptions
): Promise<{ key: string; bucket: string; status: "presigned"; url: string }>;
export function generatePresignedDownloadUrl(
  key: string,
  options?: Omit<PresignOptions, "contentType">
): Promise<{ key: string; bucket: string; status: "presigned"; url: string }>;
export function clearServiceCache(): void;
