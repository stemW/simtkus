Prerequisites
- Terraform 1.0+
- AWS CLI configured (or environment variables)
- Domain registered (simtkus.com) and Hosted Zone ID available in Route53

Quick steps
1. Populate variables (example):

   terraform init
   terraform apply -var="domain_name=simtkus.com" -var="hosted_zone_id=Z123..." -var="profile=default"

2. Terraform will:
   - create an S3 bucket named `simtkus.com` (private) for static hosting via CloudFront. If your media uploads bucket is `stemtk`, leave it separate; do not overwrite it with this bucket.
   - request an ACM cert in `us-east-1` and create the validation DNS record in your hosted zone
   - create a CloudFront distribution with OAI to serve the private S3 bucket
   - create a Route53 ALIAS A record for `simtkus.com` pointing to the CloudFront distribution

Notes
- Before applying, ensure Route53 is authoritative for the domain (registrar delegates NS to Route53). The ACM DNS validation record is created by Terraform and will validate automatically once DNS propagates.
- This setup uses a private S3 bucket served through CloudFront (recommended). Browser uploads should be implemented via presigned URLs from your server.

