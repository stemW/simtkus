# Nginx + Certbot setup for simtkus.com

This document shows commands to install nginx, obtain Let's Encrypt certificates with Certbot, and configure the system to proxy to the local Node app (port 8080).

Assumptions
- You're running on a Linux server (Ubuntu/Debian). If on another distro or macOS, adapt package manager and service commands.
- DNS for `simtkus.com` already points to this host (you confirmed this).
- Node app runs on `127.0.0.1:8080` (the default in `server.js`).

1) Install nginx and Certbot (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
```

2) Create webroot for ACME challenge (used by Certbot)
```bash
sudo mkdir -p /var/www/letsencrypt
sudo chown -R $USER:www-data /var/www/letsencrypt
sudo chmod -R 755 /var/www/letsencrypt
```

3) Place nginx site file
- Copy `deploy/nginx/simtk.conf` to `/etc/nginx/sites-available/simtk` and create a symlink:
```bash
sudo cp deploy/nginx/simtk.conf /etc/nginx/sites-available/simtk
sudo ln -sf /etc/nginx/sites-available/simtk /etc/nginx/sites-enabled/simtk
```

4) Test nginx config and restart
```bash
sudo nginx -t
sudo systemctl restart nginx
```

5) Obtain TLS cert with Certbot (nginx plugin)
- Recommended (Certbot will update nginx config automatically):
```bash
sudo certbot --nginx -d simtkus.com -d www.simtkus.com
```
- If you prefer webroot mode (safer when nginx config is custom):
```bash
sudo certbot certonly --webroot -w /var/www/letsencrypt -d simtkus.com -d www.simtkus.com
# then ensure ssl_certificate paths in the nginx site point to the certs above
```

6) Open firewall (ufw) if enabled
```bash
sudo ufw allow 'Nginx Full'
sudo ufw reload
```

7) Update `.env` for production TLS
- Set `FORCE_SECURE=true`
- Set `APP_URL=https://simtkus.com`

8) Restart Node app (example using `nohup`)
```bash
# run as the app user (no sudo required if binding to 8080)
PORT=8080 nohup node server.js > app.log 2>&1 &
```

9) Verify endpoints
```bash
# local test on the server
curl -v http://localhost:8080/status
curl -vk https://simtkus.com/status
```

10) Renewal
- Certbot will install a systemd timer; test with:
```bash
sudo certbot renew --dry-run
```

Notes
- If your provider blocks ports 80/443, Certbot cannot perform HTTP-01 validation. In that case use DNS-01 with your DNS provider plugin or provision certs elsewhere and upload them.
- If you prefer CloudFront/Load Balancer, I can scaffold Terraform for that instead.

