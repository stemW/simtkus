#!/usr/bin/env bash
# Helper to test nginx + Node proxy for smarkwm
set -euo pipefail

echo "1) Test nginx config"
sudo nginx -t

echo "2) Restart nginx"
sudo systemctl restart nginx || sudo service nginx restart || true

# Check services
echo "Listening ports (top):"
ss -tlnp | sed -n '1,200p' || lsof -iTCP -sTCP:LISTEN -P -n | sed -n '1,200p'

# Test local Node
echo "3) Test local Node status"
curl -sS http://127.0.0.1:8080/status || echo "Failed to connect to local Node on 127.0.0.1:8080"

# Test via nginx (HTTP should redirect to HTTPS)
echo "4) Test HTTP -> HTTPS redirection and HTTPS status"
curl -I http://smarkwm.online || true
curl -vk https://smarkwm.online/status || true

# Check certbot renewal (dry-run)
echo "5) Dry-run certbot renew (no changes)"
sudo certbot renew --dry-run || true

echo "Done. Review logs at /var/log/nginx/smarkwm.* and app.log for Node output." 
