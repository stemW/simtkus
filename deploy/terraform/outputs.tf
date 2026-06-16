output "bucket_name" {
  value = aws_s3_bucket.site_bucket.bucket
}

output "cloudfront_domain" {
  value = aws_cloudfront_distribution.cdn.domain_name
}

output "certificate_arn" {
  value = aws_acm_certificate.cert.arn
}
