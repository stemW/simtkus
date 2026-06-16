# Deploy guide

Files added:

- `deploy/terraform/*` — Terraform code to provision S3 bucket (private), ACM cert (us-east-1), CloudFront distribution with OAI, and Route53 ALIAS record.
 - `deploy/terraform/*` — Terraform code to provision S3 bucket (private), ACM cert (us-east-1), CloudFront distribution with OAI, and Route53 ALIAS record. You can replace Route53 parts with Alibaba Cloud DNS (`alicloud_alidns_record`) if using Alibaba for DNS.
- `deploy/nginx/simtk.conf` — example nginx proxy config for LetsEncrypt TLS and proxy to local Node server.
- `deploy/iam/s3_policy.json` — example IAM policy for server to upload to S3.

Quick checklist

1. Ensure your domain `simtkus.com` is registered and you have a Route53 hosted zone; get the `hosted_zone_id`.
	- If you use Alibaba Cloud for DNS, ensure the domain is managed in Alibaba Cloud DNS (Console → Domains) and note the zone/domain name. Terraform provider `alicloud` can manage `alicloud_alidns_record` resources.
2. Configure AWS CLI or set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in your environment.
3. Run Terraform in `deploy/terraform`:

```bash
cd deploy/terraform
terraform init
terraform apply -var="domain_name=simtkus.com" -var="hosted_zone_id=Z123..." -var="profile=default"
```

4. After `apply` completes, Terraform outputs the CloudFront domain — update DNS/registrar if required (Route53 should already be authoritative).
5. Provision TLS for your origin (if you proxy directly to your server) using Certbot and the `deploy/nginx/simtk.conf` snippet.
6. Update your server `.env` (buckets):

```
HOSTNAME=https://simtkus.com
GOOGLE_REDIRECT_URI=https://simtkus.com/auth/google/callback
S3_BUCKET_NAME=stemtk   # reels/media bucket actually used by the app
AWS_REGION=us-east-1
```

If you also create a static-site bucket named `simtkus.com` (for CloudFront/S3 hosting), keep it separate from the `stemtk` media bucket.

Notes
- The Terraform here creates a private S3 bucket and a CloudFront distribution that serves content over HTTPS using an ACM certificate (DNS-validated). Browser uploads should be done via presigned URLs from your Node server so AWS credentials are never exposed to clients.
- Replace `profile` usage with environment credentials or instance role in production.

