# InfluencerPro Server Monitor

A single-file PHP dashboard for watching and fixing the InfluencerPro VPS. It covers services, Supervisor queue workers, Laravel, MySQL, Redis, disks, security, Netdata alarms and logs, and most problems it finds come with a one-click fix.

**Files**

| File | Purpose |
|---|---|
| `status.php` | The dashboard (PHP 8.1+, needs `exec()` enabled) |
| `server-monitor.sudoers` | The exact root commands the dashboard is allowed to run |
| `README.md` | This file |

---

## Setup (about 5 minutes)

### 1. Set the password and config

Generate a password hash on the server:

```bash
php -r "echo password_hash('YourStrongPass', PASSWORD_DEFAULT), PHP_EOL;"
```

Paste the output into `status.php`:

```php
const ADMIN_PASSWORD_HASH = '$2y$10$....';
```

While you're in the config block at the top of the file, check these settings:

| Setting | What to check |
|---|---|
| `LARAVEL_PATH` | Folder that contains `artisan` and `.env` (default `/var/www/influencerpro`) |
| `SUPERVISOR_GROUPS` | Your Supervisor program names (default `influencerpro-realtime`, `influencerpro-default`) |
| `QUEUES` | Laravel queue names (default `realtime`, `default`) |
| `NETDATA_LINK` | URL you open Netdata at. Leave empty to hide the button |
| `ALLOWED_IPS` | Optional. Your IP(s) only, e.g. `['203.0.113.10']` |
| `EXTRA_SSL_DOMAINS` | Extra domains to check SSL expiry for (`APP_URL` is checked automatically) |

Then upload `status.php` to a folder Nginx serves, e.g. `/var/www/monitor/index.php`.

### 2. Install the sudo rules

```bash
sudo visudo -cf server-monitor.sudoers && \
sudo install -m 0440 server-monitor.sudoers /etc/sudoers.d/server-monitor
```

`visudo -cf` checks the syntax first. Never skip it, because a broken sudoers file can lock you out of `sudo`.

> If you add a service to `SERVICES` or a path to `DU_PATHS` in `status.php`, add the matching lines to the sudoers file too. If you change `LARAVEL_PATH`, update the last `du` line.

### 3. Let the web user read logs and the system journal

```bash
sudo usermod -aG adm,systemd-journal www-data && sudo systemctl restart php8.4-fpm
```

Without this, the log viewer, SSH-attack and OOM checks show "permission denied".

### 4. Add extra protection in Nginx

This page can restart your services, so don't leave it open to everyone. Put one of these in front of it as well as the built-in password.

**Option A: IP restriction (best if your IP is fixed)**

```nginx
server {
    listen 443 ssl;
    server_name monitor.yourdomain.com;
    root /var/www/monitor;
    index index.php;

    allow 203.0.113.10;   # your IP
    deny all;

    location / { try_files $uri /index.php?$query_string; }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_read_timeout 200;   # artisan / du actions can take a while
    }
}
```

**Option B: HTTP basic auth (works from anywhere)**

```bash
sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/.monitor_htpasswd admin
```

```nginx
location / {
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.monitor_htpasswd;
    try_files $uri /index.php?$query_string;
}
```

Then test and reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Use HTTPS (`sudo certbot --nginx -d monitor.yourdomain.com`) so the password isn't sent in plain text.

---

## Local testing

The dashboard reads Linux internals (`/proc`, `systemctl`, `journalctl`), so it has to run on Linux. On Windows use **WSL (Ubuntu)**, and on macOS use **Docker**. Running it straight on macOS or Windows PHP won't work.

### Option 1: Linux or WSL (quickest)

```bash
# 1. Install PHP if needed
sudo apt install -y php-cli php-mysql

# 2. Make a test copy with a known password ("test")
mkdir -p ~/monitor-test && cd ~/monitor-test
HASH=$(php -r "echo password_hash('test', PASSWORD_DEFAULT);")
sed "s|const ADMIN_PASSWORD_HASH = 'CHANGE_ME';|const ADMIN_PASSWORD_HASH = '$HASH';|" \
    /path/to/status.php > index.php

# 3. Run PHP's built-in server with all errors shown
php -d display_errors=1 -d error_reporting=E_ALL -S 127.0.0.1:8099
```

Open <http://127.0.0.1:8099> and log in with `test`.

### Option 2: Docker (macOS, or to keep your machine clean)

```bash
mkdir -p ~/monitor-test && cd ~/monitor-test
# create index.php with the test password as in Option 1, step 2, then:
docker run --rm -it -p 8099:8099 -v "$PWD":/app -w /app php:8.4-cli \
  bash -c "docker-php-ext-install pdo_mysql >/dev/null && php -S 0.0.0.0:8099"
```

Open <http://127.0.0.1:8099>.

### What to expect locally

Your laptop isn't the VPS, so a lot of the page will be red or empty. **That's normal and doesn't mean the dashboard is broken.**

- Services such as Nginx, MySQL and Supervisor show **not installed** or **DOWN**.
- Laravel shows "not found" unless you point `LARAVEL_PATH` at a local copy of the app.
- MySQL, Redis and queues show connection errors unless those services run locally.
- Action buttons return "sudo rule missing". The sudoers file is only installed on the server.

What **should** work locally:

- [ ] Login page appears; a wrong password is rejected; 5 wrong tries lock you out for 15 minutes
- [ ] The dashboard loads with no PHP warnings, notices or fatal errors anywhere on the page
- [ ] The Live CPU, RAM, load and network cards update every 3 seconds and the sparklines move
- [ ] Disks and Top processes tables are filled in
- [ ] The log viewer loads "Journal · Kernel" (or shows a clear error message)
- [ ] Logout works

### Command-line checks

Run these while the test server is running:

```bash
cd ~/monitor-test
php -l index.php                                   # syntax check → "No syntax errors detected"

C=cookies.txt
curl -s -c $C -b $C -d password=test http://127.0.0.1:8099/ -o /dev/null -w "login: %{http_code}\n"   # expect 302
curl -s -b $C http://127.0.0.1:8099/ -o page.html -w "page: %{http_code}, %{time_total}s\n"           # expect 200
grep -iE "fatal|warning:|notice:|deprecated" page.html || echo "no PHP errors"

curl -s -b $C "http://127.0.0.1:8099/?api=live"     # expect JSON with cpu, mem, load…

# Security: these must be REJECTED
CSRF=$(grep -oP 'const CSRF = "\K[0-9a-f]+' page.html)
curl -s -b $C -H "X-CSRF: $CSRF" -H 'Content-Type: application/json' \
     -d '{"action":"svc","target":"nginx;rm -rf /","op":"restart"}' "http://127.0.0.1:8099/?api=action"
# → {"ok":false,"title":"Rejected",...}
curl -s -b $C -H "X-CSRF: wrong" -d '{}' "http://127.0.0.1:8099/?api=action"
# → {"ok":false,"title":"Blocked",...}
curl -s "http://127.0.0.1:8099/?api=live"           # no cookie → "Session expired" (401)
```

### Testing on the VPS before making it public

The safest real-world test is to run it on the server without exposing it, using an SSH tunnel:

```bash
# on the VPS — run as www-data so sudo rules and permissions match production
sudo -u www-data php -S 127.0.0.1:8099 -t /var/www/monitor

# on your laptop
ssh -L 8099:127.0.0.1:8099 user@your-vps-ip
```

Open <http://127.0.0.1:8099> on your laptop. Everything should now be green or show real values. Try a harmless action like **Test Nginx config**. If it says "sudo rule missing", re-check step 2. Press `Ctrl+C` to stop the test server when you're done.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Page says `exec() is disabled` | Remove `exec` from `disable_functions` in `/etc/php/8.4/fpm/php.ini`, then restart PHP-FPM |
| Actions say "sudo rule missing" | Sudoers file not installed or path differs. Check with `sudo -u www-data sudo -n -l` |
| Logs say "Permission denied" | Redo step 3, then restart PHP-FPM |
| Supervisor card is red: "Cannot read Supervisor status" | `/usr/bin/supervisorctl` is missing from the sudoers file, or Supervisor is stopped |
| Queue backlog is empty | Check `QUEUES` names and `QUEUE_CONNECTION` (only `redis` and `database` are supported) |
| Netdata "API not reachable" | Netdata must listen on `127.0.0.1:19999` (or change `NETDATA_API`) |
| Restarting PHP-FPM shows "Request failed" | Expected, because the page itself runs on PHP-FPM. Refresh after a few seconds |
| Action buttons time out | Raise `fastcgi_read_timeout` in Nginx (see step 4) |

Every action is recorded in `storage/logs/server-monitor-audit.log`, and you can also see it under **Tools → Action audit log** on the dashboard.

php -S 127.0.0.1:8080