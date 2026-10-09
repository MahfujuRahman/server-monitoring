<?php
/**
 * InfluencerPro — Server Monitor & Control Panel (single file)
 * Requires PHP 8.1+, exec() enabled, and the sudoers rules in server-monitor.sudoers
 */
declare(strict_types=1);

/* ═══════════════════════════════ CONFIG ═══════════════════════════════ */

const APP_TITLE = 'InfluencerPro Server';

// Generate with:  php -r "echo password_hash('your-strong-password', PASSWORD_DEFAULT), PHP_EOL;"
const ADMIN_PASSWORD_HASH = '$2y$12$Vr/i50rApA6TDXn49KE85upUWjIuYynlYXsTiBlCMoya3WySuO58S';  // change this to your own hash
const ALLOWED_IPS         = [];      // e.g. ['203.0.113.10'] — empty = any IP (password still required)
const SESSION_IDLE_MIN    = 120;

const LARAVEL_PATH = '/var/www/influencerpro';   // folder that contains artisan + .env
const PHP_BIN      = '/usr/bin/php8.4';
const PHP_FPM_BIN  = '/usr/sbin/php-fpm8.4';
const PHP_FPM_LOG  = '/var/log/php8.4-fpm.log';

// systemd unit => label   (every unit here also needs lines in the sudoers file)
const SERVICES = [
    'nginx'        => 'Nginx',
    'php8.4-fpm'   => 'PHP-FPM',
    'mysql'        => 'MySQL',
    'redis-server' => 'Redis',
    'supervisor'   => 'Supervisor',
    'cron'         => 'Cron (scheduler)',
    'netdata'      => 'Netdata',
];
const RELOADABLE = ['nginx', 'php8.4-fpm'];

const SUPERVISOR_GROUPS  = ['influencerpro-realtime', 'influencerpro-default'];
const QUEUES             = ['realtime', 'default'];
const QUEUE_BACKLOG_WARN = 500;

const NETDATA_API       = 'http://127.0.0.1:19999';
const NETDATA_LINK      = '';        // URL you use to open Netdata (tunnel / Netdata Cloud). Empty = hide button
const EXTRA_SSL_DOMAINS = [];        // APP_URL host from .env is checked automatically
const DU_PATHS          = ['/', '/var', '/var/log', LARAVEL_PATH];

const SENSITIVE_PORTS = [3306 => 'MySQL', 33060 => 'MySQL X', 6379 => 'Redis', 19999 => 'Netdata',
                         9001 => 'Supervisor web', 11211 => 'Memcached', 9000 => 'PHP-FPM'];

const ARTISAN = [   // key => [artisan args, confirm text|null]
    'queue:restart'   => ['queue:restart', null],
    'optimize:clear'  => ['optimize:clear', null],
    'optimize'        => ['optimize', null],
    'queue:retry-all' => ['queue:retry all', 'Retry ALL failed jobs?'],
    'queue:flush'     => ['queue:flush', 'Permanently DELETE all failed jobs?'],
    'up'              => ['up', 'Take the app out of maintenance mode?'],
    'migrate:status'  => ['migrate:status', null],
    'schedule:list'   => ['schedule:list', null],
    'about'           => ['about', null],
];

/* ═══════════════════════════════ BOOTSTRAP ═══════════════════════════════ */

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');

$ip = $_SERVER['REMOTE_ADDR'] ?? '';
if (ALLOWED_IPS && !in_array($ip, ALLOWED_IPS, true)) { http_response_code(403); exit('Forbidden'); }
if (!function_exists('exec')) { exit('exec() is disabled in php.ini (disable_functions). This dashboard needs it.'); }
if (ADMIN_PASSWORD_HASH === 'CHANGE_ME') {
    exit('Set ADMIN_PASSWORD_HASH at the top of this file first. Generate one with: php -r "echo password_hash(\'your-password\', PASSWORD_DEFAULT), PHP_EOL;"');
}

session_name('srvmon');
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Strict',
    'secure'   => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();

if (isset($_GET['logout'])) { session_destroy(); header('Location: ?'); exit; }

if (!empty($_SESSION['auth']) && time() - ($_SESSION['seen'] ?? 0) > SESSION_IDLE_MIN * 60) {
    $_SESSION = [];
}

if (empty($_SESSION['auth'])) {
    if (isset($_GET['api'])) { http_response_code(401); jsonOut(['ok' => false, 'title' => 'Session expired', 'out' => 'Reload the page and log in again.']); }
    $err = '';
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['password'])) {
        if (loginLocked($ip)) {
            $err = 'Too many attempts. Try again in 15 minutes.';
        } elseif (password_verify((string)$_POST['password'], ADMIN_PASSWORD_HASH)) {
            session_regenerate_id(true);
            $_SESSION['auth'] = true;
            $_SESSION['seen'] = time();
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            loginReset($ip);
            audit('login');
            header('Location: ?'); exit;
        } else {
            loginFail($ip); sleep(1); $err = 'Wrong password.';
        }
    }
    renderLogin($err); exit;
}
$_SESSION['seen'] = time();
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));

/* ═══════════════════════════════ API ROUTES ═══════════════════════════════ */

$api = $_GET['api'] ?? '';
if ($api === 'live') {
    jsonOut(liveSample(600));
}
if ($api === 'log') {
    session_write_close();
    jsonOut(readLog((string)($_GET['key'] ?? ''), (int)($_GET['lines'] ?? 300)));
}
if ($api === 'action') {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !hash_equals($_SESSION['csrf'], (string)($_SERVER['HTTP_X_CSRF'] ?? ''))) {
        http_response_code(403); jsonOut(['ok' => false, 'title' => 'Blocked', 'out' => 'Invalid CSRF token. Reload the page.']);
    }
    session_write_close();
    $in = json_decode((string)file_get_contents('php://input'), true) ?: [];
    jsonOut(handleAction($in));
}

/* ═══════════════════════════════ HELPERS ═══════════════════════════════ */

function jsonOut(array $data): never {
    header('Content-Type: application/json');
    echo json_encode($data, JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function run(string $cmd, int $timeout = 15): array {
    $out = []; $code = 0;
    exec('timeout ' . $timeout . ' bash -c ' . escapeshellarg($cmd) . ' 2>&1', $out, $code);
    $text = implode("\n", $out);
    if ($code === 124) $text .= "\n(timed out after {$timeout}s)";
    return ['code' => $code, 'out' => trim($text)];
}
function sh(string $cmd, int $timeout = 15): string { return run($cmd, $timeout)['out']; }

function cached(string $key, int $ttl, callable $fn): mixed {
    $f = sys_get_temp_dir() . '/srvmon_cache_' . md5($key) . '.json';
    if (is_file($f) && time() - filemtime($f) < $ttl) {
        $d = json_decode((string)file_get_contents($f), true);
        if (is_array($d) && array_key_exists('v', $d)) return $d['v'];
    }
    $v = $fn();
    @file_put_contents($f, json_encode(['v' => $v], JSON_INVALID_UTF8_SUBSTITUTE));
    return $v;
}
function clearCache(): void { foreach (glob(sys_get_temp_dir() . '/srvmon_cache_*.json') ?: [] as $f) @unlink($f); }

function auditFile(): string {
    $d = LARAVEL_PATH . '/storage/logs';
    return is_writable($d) ? $d . '/server-monitor-audit.log' : sys_get_temp_dir() . '/srvmon-audit.log';
}
function audit(string $msg): void {
    @file_put_contents(auditFile(), date('Y-m-d H:i:s') . '  ' . ($_SERVER['REMOTE_ADDR'] ?? '-') . '  ' . $msg . "\n", FILE_APPEND | LOCK_EX);
}

function attemptsFile(string $ip): string { return sys_get_temp_dir() . '/srvmon_login_' . md5($ip); }
function loginLocked(string $ip): bool {
    $f = attemptsFile($ip);
    if (!is_file($f)) return false;
    [$n, $t] = (json_decode((string)file_get_contents($f), true) ?: []) + [0, 0];
    return $n >= 5 && time() - $t < 900;
}
function loginFail(string $ip): void {
    $f = attemptsFile($ip);
    $d = is_file($f) ? ((json_decode((string)file_get_contents($f), true) ?: []) + [0, 0]) : [0, 0];
    if (time() - $d[1] > 900) $d = [0, 0];
    file_put_contents($f, json_encode([$d[0] + 1, time()]));
}
function loginReset(string $ip): void { @unlink(attemptsFile($ip)); }

function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function fmtBytes(float|int|null $b, int $dec = 1): string {
    if ($b === null) return '—';
    $u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']; $i = 0;
    while ($b >= 1024 && $i < 5) { $b /= 1024; $i++; }
    return round($b, $i ? $dec : 0) . ' ' . $u[$i];
}
function fmtDur(float|int|null $s): string {
    if ($s === null) return '—';
    $s = (int)$s; $d = intdiv($s, 86400); $hh = intdiv($s % 86400, 3600); $m = intdiv($s % 3600, 60);
    if ($d) return "{$d}d {$hh}h";
    if ($hh) return "{$hh}h {$m}m";
    if ($m) return "{$m}m";
    return "{$s}s";
}
function lvl(float $v, float $warn, float $crit): string { return $v >= $crit ? 'crit' : ($v >= $warn ? 'warn' : 'ok'); }
function bar(float $pct, string $lvl): string {
    return '<div class="bar"><span class="' . $lvl . '" style="width:' . min(100, max(0, $pct)) . '%"></span></div>';
}
function badge(string $lvl, string $text): string { return '<span class="badge ' . $lvl . '">' . h($text) . '</span>'; }
function btn(string $label, array $spec, string $cls = '', ?string $confirm = null): string {
    if ($confirm) $spec['confirm'] = $confirm;
    return '<button class="btn ' . $cls . '" data-act="' . h(json_encode($spec)) . '">' . h($label) . '</button>';
}
function logBtn(string $key, string $label = 'Logs'): string {
    return '<button class="btn ghost" data-log="' . h($key) . '">' . h($label) . '</button>';
}

function tailFile(string $file, int $lines = 300): string {
    $size = filesize($file);
    if (!$size) return '';
    $chunk = (int)min($size, max(131072, $lines * 600));
    $fh = fopen($file, 'rb');
    fseek($fh, $size - $chunk);
    $data = (string)fread($fh, $chunk);
    fclose($fh);
    $arr = explode("\n", rtrim($data));
    if ($size > $chunk) array_shift($arr);
    return implode("\n", array_slice($arr, -$lines));
}

/* ═══════════════════════════════ SYSTEM DATA ═══════════════════════════════ */

function cpuCores(): int {
    return max(1, preg_match_all('/^processor\s*:/m', (string)@file_get_contents('/proc/cpuinfo')));
}
function uptimeSeconds(): float { return (float)explode(' ', (string)@file_get_contents('/proc/uptime'))[0]; }

function cpuRaw(): array {
    $f = preg_split('/\s+/', trim((string)strtok((string)file_get_contents('/proc/stat'), "\n")));
    array_shift($f);
    return array_map('intval', array_pad($f, 8, 0));
}
function netRaw(): array {
    $rx = $tx = 0;
    foreach (array_slice(@file('/proc/net/dev') ?: [], 2) as $l) {
        [$if, $d] = array_pad(explode(':', $l, 2), 2, '');
        $if = trim($if);
        if ($if === '' || $if === 'lo' || preg_match('/^(veth|docker|br-|virbr)/', $if)) continue;
        $p = preg_split('/\s+/', trim($d));
        $rx += (int)($p[0] ?? 0); $tx += (int)($p[8] ?? 0);
    }
    return [$rx, $tx];
}
function memInfo(): array {
    $m = [];
    foreach (@file('/proc/meminfo') ?: [] as $l) if (preg_match('/^(\w+):\s+(\d+)/', $l, $x)) $m[$x[1]] = (int)$x[2] * 1024;
    $total = $m['MemTotal'] ?? 0; $used = $total - ($m['MemAvailable'] ?? 0);
    $st = $m['SwapTotal'] ?? 0; $su = $st - ($m['SwapFree'] ?? 0);
    return ['total' => $total, 'used' => $used, 'pct' => $total ? round($used / $total * 100, 1) : 0,
            'cache' => ($m['Cached'] ?? 0) + ($m['Buffers'] ?? 0),
            'swap_total' => $st, 'swap_used' => $su, 'swap_pct' => $st ? round($su / $st * 100, 1) : 0];
}
function liveSample(int $ms = 500): array {
    $c1 = cpuRaw(); [$r1, $t1] = netRaw(); $s = microtime(true);
    usleep($ms * 1000);
    $c2 = cpuRaw(); [$r2, $t2] = netRaw(); $dt = max(0.001, microtime(true) - $s);
    $d = []; foreach ($c2 as $i => $v) $d[$i] = $v - ($c1[$i] ?? 0);
    $total = max(1, array_sum(array_slice($d, 0, 8)));   // user nice system idle iowait irq softirq steal
    $pct = fn($x) => round($x / $total * 100, 1);
    $load = sys_getloadavg() ?: [0, 0, 0];
    $root = @disk_total_space('/') ?: 0;
    return [
        'cpu' => $pct($total - $d[3] - $d[4]), 'user' => $pct($d[0] + $d[1]), 'system' => $pct($d[2] + $d[5] + $d[6]),
        'iowait' => $pct($d[4]), 'steal' => $pct($d[7]),
        'load' => array_map(fn($x) => round((float)$x, 2), $load), 'cores' => cpuCores(),
        'mem' => memInfo(),
        'rx' => (int)max(0, ($r2 - $r1) / $dt), 'tx' => (int)max(0, ($t2 - $t1) / $dt),
        'disk' => $root ? round(($root - (float)disk_free_space('/')) / $root * 100, 1) : 0,
        'uptime' => uptimeSeconds(), 'time' => date('H:i:s'),
    ];
}

function systemInfo(): array {
    $os = 'Linux';
    if (preg_match('/^PRETTY_NAME="?([^"\n]+)/m', (string)@file_get_contents('/etc/os-release'), $m)) $os = $m[1];
    $model = preg_match('/^model name\s*:\s*(.+)$/m', (string)@file_get_contents('/proc/cpuinfo'), $m) ? trim($m[1]) : '—';
    $pkgs = is_readable('/var/run/reboot-required.pkgs') ? array_filter(array_map('trim', file('/var/run/reboot-required.pkgs'))) : [];
    return [
        'host' => gethostname(), 'os' => $os, 'kernel' => php_uname('r'), 'uptime' => uptimeSeconds(),
        'cpu_model' => $model, 'cores' => cpuCores(), 'php' => PHP_VERSION, 'time' => date('Y-m-d H:i:s T'),
        'ip' => $_SERVER['SERVER_ADDR'] ?? '', 'reboot' => is_file('/var/run/reboot-required'), 'reboot_pkgs' => array_values(array_unique($pkgs)),
        'updates' => aptUpdates(), 'virt' => trim(sh('systemd-detect-virt 2>/dev/null', 3)) ?: '—',
    ];
}
function aptUpdates(): ?array {
    return cached('apt', 3600, function () {
        if (!is_executable('/usr/lib/update-notifier/apt-check')) return null;
        $o = sh('/usr/lib/update-notifier/apt-check', 40);
        return preg_match('/(\d+);(\d+)/', $o, $m) ? ['all' => (int)$m[1], 'security' => (int)$m[2]] : null;
    });
}

function disks(): array {
    $inodes = [];
    foreach (array_slice(explode("\n", sh('df -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay')), 1) as $l) {
        $p = preg_split('/\s+/', trim($l), 6);
        if (count($p) === 6) $inodes[$p[5]] = (int)rtrim($p[4], '%');
    }
    $res = [];
    foreach (array_slice(explode("\n", sh('df -PT -B1 -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs')), 1) as $l) {
        $p = preg_split('/\s+/', trim($l), 7);
        if (count($p) < 7) continue;
        [$fs, $type, $size, $used, $avail, $pct, $mnt] = $p;
        if (str_starts_with($mnt, '/snap') || $mnt === '/boot/efi') continue;
        $res[] = ['fs' => $fs, 'type' => $type, 'size' => (int)$size, 'used' => (int)$used, 'avail' => (int)$avail,
                  'pct' => (int)rtrim($pct, '%'), 'mount' => $mnt, 'ipct' => $inodes[$mnt] ?? null];
    }
    return $res;
}

function serviceInfo(string $unit): array {
    $raw = sh('systemctl show ' . escapeshellarg($unit) . ' --no-pager -p LoadState -p ActiveState -p SubState -p MainPID'
        . ' -p ActiveEnterTimestampMonotonic -p MemoryCurrent -p NRestarts -p TasksCurrent -p UnitFileState', 5);
    $p = [];
    foreach (explode("\n", $raw) as $l) if (str_contains($l, '=')) { [$k, $v] = explode('=', $l, 2); $p[$k] = $v; }
    $mem = $p['MemoryCurrent'] ?? '';
    $tasks = $p['TasksCurrent'] ?? '';
    $mono = (int)($p['ActiveEnterTimestampMonotonic'] ?? 0);
    $active = ($p['ActiveState'] ?? '') === 'active';
    return [
        'exists' => ($p['LoadState'] ?? '') === 'loaded', 'active' => $active,
        'state' => ($p['ActiveState'] ?? 'unknown') . ' (' . ($p['SubState'] ?? '?') . ')',
        'pid' => (int)($p['MainPID'] ?? 0),
        'mem' => (ctype_digit($mem) && strlen($mem) < 16) ? (int)$mem : null,
        'tasks' => (ctype_digit($tasks) && strlen($tasks) < 16) ? (int)$tasks : null,
        'restarts' => (int)($p['NRestarts'] ?? 0),
        'since' => ($active && $mono > 0) ? max(0, uptimeSeconds() - $mono / 1e6) : null,
        'enabled' => $p['UnitFileState'] ?? '',
    ];
}
function failedUnits(): array {
    $out = [];
    foreach (explode("\n", sh('systemctl --failed --no-legend --plain --no-pager', 5)) as $l) {
        $l = trim($l, " ●*\t");
        if ($l !== '') $out[] = strtok($l, ' ');
    }
    return array_values(array_filter($out));
}

function supervisor(): array {
    static $cache = null;
    if ($cache !== null) return $cache;
    $r = run('sudo -n /usr/bin/supervisorctl status', 10);
    $procs = [];
    foreach (explode("\n", $r['out']) as $l) {
        if (!preg_match('/^(\S+)\s+(RUNNING|STOPPED|STARTING|BACKOFF|STOPPING|EXITED|FATAL|UNKNOWN)\s*(.*)$/', trim($l), $m)) continue;
        $procs[] = ['name' => $m[1], 'group' => explode(':', $m[1])[0], 'state' => $m[2], 'info' => $m[3]];
    }
    return $cache = ['procs' => $procs, 'error' => (!$procs && $r['out'] !== '') ? $r['out'] : ''];
}

function topProcs(string $by): array {
    $sort = $by === 'mem' ? 'rss' : 'pcpu';
    $out = [];
    foreach (explode("\n", sh("ps -eo pid,user:16,pcpu,pmem,rss,etimes,args --sort=-$sort --no-headers | head -n 10", 5)) as $l) {
        $p = preg_split('/\s+/', trim($l), 7);
        if (count($p) < 7) continue;
        $out[] = ['pid' => $p[0], 'user' => $p[1], 'cpu' => $p[2], 'mem' => $p[3], 'rss' => (int)$p[4] * 1024, 'age' => (int)$p[5], 'cmd' => mb_strimwidth($p[6], 0, 110, '…')];
    }
    return $out;
}

function listeningPorts(): array {
    $r = run('sudo -n /usr/bin/ss -tulpnH', 5);
    if ($r['code'] !== 0) $r = run('ss -tulnH', 5);
    $res = [];
    foreach (explode("\n", $r['out']) as $l) {
        $p = preg_split('/\s+/', trim($l), 7);
        if (count($p) < 5) continue;
        $local = $p[4];
        $pos = strrpos($local, ':');
        if ($pos === false) continue;
        $addr = substr($local, 0, $pos); $port = (int)substr($local, $pos + 1);
        $addr = preg_replace('/%.*$/', '', $addr);
        $proc = preg_match('/"([^"]+)"/', $p[6] ?? '', $m) ? $m[1] : '';
        $public = in_array($addr, ['0.0.0.0', '*', '[::]', '::'], true);
        $key = $p[0] . $port . ($public ? 'pub' : $addr);
        $res[$key] = ['proto' => $p[0], 'addr' => $addr, 'port' => $port, 'proc' => $proc, 'public' => $public];
    }
    usort($res, fn($a, $b) => $a['port'] <=> $b['port']);
    return $res;
}
function ufwStatus(): string {
    $r = run('sudo -n /usr/sbin/ufw status', 5);
    if ($r['code'] !== 0) return 'unknown';
    return str_contains($r['out'], 'Status: active') ? 'active' : 'inactive';
}

function journalAccess(): bool {
    return !preg_match('/insufficient permissions|not seeing messages/i', sh('journalctl -n 1 -q --no-pager', 5));
}
function sshFailures(): array {
    return cached('ssh', 300, function () {
        $o = sh("journalctl _COMM=sshd _COMM=sshd-session -S -24h --no-pager -q -o cat 2>/dev/null | grep -E 'Failed password|Invalid user|authentication failure'", 20);
        $lines = array_values(array_filter(explode("\n", $o)));
        $ips = [];
        foreach ($lines as $l) if (preg_match('/from ([0-9a-fA-F:.]+)/', $l, $m)) $ips[$m[1]] = ($ips[$m[1]] ?? 0) + 1;
        arsort($ips);
        return ['count' => count($lines), 'top' => array_slice($ips, 0, 6, true)];
    });
}
function oomEvents(): array {
    return cached('oom', 300, fn() => array_values(array_filter(explode("\n",
        sh("journalctl -k -S -7d --no-pager -q -o short-iso 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process' | tail -n 8", 20)))));
}
function fpmWarnings(): array {
    if (!is_readable(PHP_FPM_LOG)) return ['readable' => false, 'count' => 0, 'last' => ''];
    $hits = array_values(array_filter(explode("\n", tailFile(PHP_FPM_LOG, 3000)), fn($l) => str_contains($l, 'max_children')));
    return ['readable' => true, 'count' => count($hits), 'last' => $hits ? end($hits) : ''];
}
function nginxErrorStats(): array {
    $f = '/var/log/nginx/error.log';
    if (!is_readable($f)) return ['readable' => false];
    $lines = explode("\n", tailFile($f, 3000));
    $c = fn(string $needle) => count(array_filter($lines, fn($l) => str_contains($l, $needle)));
    return ['readable' => true, 'timeout' => $c('upstream timed out'), 'crit' => $c('[crit]') + $c('[emerg]') + $c('[alert]'), 'refused' => $c('Connection refused')];
}

function sslCerts(): array {
    $domains = EXTRA_SSL_DOMAINS;
    $url = laravelEnv()['APP_URL'] ?? '';
    if (str_starts_with($url, 'https://') && ($host = parse_url($url, PHP_URL_HOST))) array_unshift($domains, $host);
    $out = [];
    foreach (array_unique($domains) as $d) {
        $out[$d] = cached('ssl_' . $d, 21600, function () use ($d) {
            $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false, 'SNI_enabled' => true, 'peer_name' => $d]]);
            $c = @stream_socket_client("ssl://$d:443", $en, $es, 6, STREAM_CLIENT_CONNECT, $ctx);
            if (!$c) return ['error' => $es ?: 'connection failed'];
            $cert = openssl_x509_parse(stream_context_get_params($c)['options']['ssl']['peer_certificate']);
            return ['expires' => $cert['validTo_time_t'] ?? 0, 'issuer' => $cert['issuer']['O'] ?? ($cert['issuer']['CN'] ?? '')];
        });
    }
    return $out;
}

function netdataAlarms(): array {
    $raw = @file_get_contents(NETDATA_API . '/api/v1/alarms', false, stream_context_create(['http' => ['timeout' => 2]]));
    if ($raw === false) return ['error' => 'Netdata API not reachable at ' . NETDATA_API, 'alarms' => []];
    $out = [];
    foreach ((json_decode($raw, true)['alarms'] ?? []) as $k => $a) {
        $out[] = ['name' => $a['name'] ?? $k, 'chart' => $a['chart'] ?? '', 'status' => $a['status'] ?? '',
                  'value' => $a['value_string'] ?? '', 'info' => $a['summary'] ?? ($a['info'] ?? ''), 'since' => (int)($a['last_status_change'] ?? 0)];
    }
    usort($out, fn($a, $b) => strcmp($a['status'], $b['status']));
    return ['alarms' => $out];
}

/* ═══════════════════════════════ LARAVEL / DB / REDIS ═══════════════════════════════ */

function laravelEnv(): array {
    static $env = null;
    if ($env !== null) return $env;
    $env = [];
    $f = LARAVEL_PATH . '/.env';
    if (!is_readable($f)) return $env;
    foreach (file($f, FILE_IGNORE_NEW_LINES) as $l) {
        $l = trim($l);
        if ($l === '' || $l[0] === '#' || !str_contains($l, '=')) continue;
        [$k, $v] = explode('=', $l, 2);
        $v = trim($v);
        if (strlen($v) >= 2 && (($v[0] === '"' && str_ends_with($v, '"')) || ($v[0] === "'" && str_ends_with($v, "'")))) $v = substr($v, 1, -1);
        $env[trim($k)] = $v;
    }
    return $env;
}
function latestLaravelLog(): string {
    $d = LARAVEL_PATH . '/storage/logs';
    $f = $d . '/laravel.log';
    $daily = glob($d . '/laravel-*.log') ?: [];
    if ($daily) {
        usort($daily, fn($a, $b) => filemtime($b) <=> filemtime($a));
        if (!is_file($f) || filemtime($daily[0]) > filemtime($f)) return $daily[0];
    }
    return $f;
}
function laravelInfo(): array {
    $e = laravelEnv();
    $log = latestLaravelLog();
    $errorsToday = 0;
    if (is_readable($log)) {
        $today = '[' . date('Y-m-d');
        foreach (explode("\n", tailFile($log, 5000)) as $l) if (str_starts_with($l, $today) && preg_match('/\.(ERROR|CRITICAL|ALERT|EMERGENCY):/', $l)) $errorsToday++;
    }
    return [
        'found' => is_file(LARAVEL_PATH . '/artisan'), 'env_found' => $e !== [],
        'env' => $e['APP_ENV'] ?? '?', 'debug' => filter_var($e['APP_DEBUG'] ?? 'false', FILTER_VALIDATE_BOOL),
        'url' => $e['APP_URL'] ?? '', 'queue' => $e['QUEUE_CONNECTION'] ?? 'sync',
        'cache' => $e['CACHE_STORE'] ?? ($e['CACHE_DRIVER'] ?? '?'), 'session' => $e['SESSION_DRIVER'] ?? '?',
        'down' => is_file(LARAVEL_PATH . '/storage/framework/down'),
        'storage_ok' => is_writable(LARAVEL_PATH . '/storage') && is_writable(LARAVEL_PATH . '/bootstrap/cache'),
        'config_cached' => is_file(LARAVEL_PATH . '/bootstrap/cache/config.php'),
        'routes_cached' => (bool)glob(LARAVEL_PATH . '/bootstrap/cache/routes-v7.php'),
        'log' => $log, 'log_size' => is_file($log) ? filesize($log) : null, 'errors_today' => $errorsToday,
    ];
}

function db(): ?PDO {
    static $pdo = false;
    if ($pdo !== false) return $pdo;
    $e = laravelEnv();
    try {
        if (($e['DB_CONNECTION'] ?? 'mysql') !== 'mysql' && ($e['DB_CONNECTION'] ?? '') !== 'mariadb') throw new RuntimeException('DB_CONNECTION is not mysql/mariadb');
        $dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', $e['DB_HOST'] ?? '127.0.0.1', $e['DB_PORT'] ?? '3306', $e['DB_DATABASE'] ?? '');
        $pdo = new PDO($dsn, $e['DB_USERNAME'] ?? '', $e['DB_PASSWORD'] ?? '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 3]);
    } catch (Throwable $t) {
        $GLOBALS['dbError'] = $t->getMessage();
        $pdo = null;
    }
    return $pdo;
}
function mysqlInfo(): array {
    $pdo = db();
    if (!$pdo) return ['error' => $GLOBALS['dbError'] ?? 'Not configured'];
    $o = [];
    try {
        $o['status'] = $pdo->query("SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime','Threads_connected','Threads_running','Slow_queries','Questions','Aborted_connects','Max_used_connections','Innodb_buffer_pool_pages_total','Innodb_buffer_pool_pages_free')")->fetchAll(PDO::FETCH_KEY_PAIR);
        $o['version'] = $pdo->query('SELECT VERSION()')->fetchColumn();
        $o['max_conn'] = (int)$pdo->query('SELECT @@max_connections')->fetchColumn();
        $o['db'] = $pdo->query('SELECT DATABASE()')->fetchColumn();
        $o['size'] = (int)$pdo->query('SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema=DATABASE()')->fetchColumn();
        $o['tables'] = $pdo->query('SELECT table_name AS n, table_rows AS r, data_length+index_length AS s FROM information_schema.tables WHERE table_schema=DATABASE() ORDER BY s DESC LIMIT 8')->fetchAll(PDO::FETCH_ASSOC);
        $o['long'] = $pdo->query("SELECT id AS id, user AS u, db AS d, time AS t, state AS st, LEFT(info,300) AS q FROM information_schema.processlist WHERE command NOT IN ('Sleep','Daemon','Binlog Dump') AND time >= 5 ORDER BY time DESC LIMIT 10")->fetchAll(PDO::FETCH_ASSOC);
    } catch (Throwable $t) { $o['error'] = $t->getMessage(); }
    try {
        $o['failed_count'] = (int)$pdo->query('SELECT COUNT(*) FROM failed_jobs')->fetchColumn();
        $o['failed'] = $pdo->query('SELECT uuid AS uuid, queue AS queue, failed_at AS failed_at, LEFT(payload, 2000) AS payload, LEFT(exception, 400) AS exception FROM failed_jobs ORDER BY id DESC LIMIT 15')->fetchAll(PDO::FETCH_ASSOC);
    } catch (Throwable) { $o['failed_count'] = null; $o['failed'] = []; }
    return $o;
}

function redisCli(string $args, int $t = 5): string {
    $e = laravelEnv();
    $pw = $e['REDIS_PASSWORD'] ?? '';
    $env = ($pw !== '' && strtolower($pw) !== 'null') ? 'REDISCLI_AUTH=' . escapeshellarg($pw) . ' ' : '';
    $host = $e['REDIS_HOST'] ?? '127.0.0.1';
    $port = $e['REDIS_PORT'] ?? '6379';
    return sh($env . 'redis-cli -h ' . escapeshellarg($host) . ' -p ' . escapeshellarg($port) . ' ' . $args, $t);
}
function redisPrefix(): string {
    $e = laravelEnv();
    if (isset($e['REDIS_PREFIX'])) return $e['REDIS_PREFIX'];
    return strtolower(trim((string)preg_replace('/[^A-Za-z0-9]+/', '_', $e['APP_NAME'] ?? 'laravel'), '_')) . '_database_';
}
function redisInfo(): array {
    $o = redisCli('INFO');
    if (!str_contains($o, 'redis_version')) return ['error' => $o ?: 'redis-cli not available'];
    $i = [];
    foreach (explode("\n", $o) as $l) {
        $l = trim($l);
        if ($l === '' || $l[0] === '#' || !str_contains($l, ':')) continue;
        [$k, $v] = explode(':', $l, 2);
        $i[$k] = $v;
    }
    $keys = 0;
    foreach ($i as $k => $v) if (preg_match('/^db\d+$/', $k) && preg_match('/keys=(\d+)/', $v, $m)) $keys += (int)$m[1];
    $i['_keys'] = $keys;
    return $i;
}
function queueSizes(): array {
    $e = laravelEnv();
    $conn = $e['QUEUE_CONNECTION'] ?? 'sync';
    $res = [];
    if ($conn === 'redis') {
        $prefix = redisPrefix();
        $db = escapeshellarg($e['REDIS_DB'] ?? '0');
        foreach (QUEUES as $q) {
            $k = $prefix . 'queues:' . $q;
            $res[$q] = [
                'pending'  => (int)redisCli("-n $db --raw LLEN " . escapeshellarg($k)),
                'delayed'  => (int)redisCli("-n $db --raw ZCARD " . escapeshellarg($k . ':delayed')),
                'reserved' => (int)redisCli("-n $db --raw ZCARD " . escapeshellarg($k . ':reserved')),
            ];
        }
    } elseif ($conn === 'database' && ($pdo = db())) {
        $st = $pdo->prepare('SELECT COUNT(*) AS total, COALESCE(SUM(reserved_at IS NOT NULL),0) AS reserved, COALESCE(SUM(available_at > UNIX_TIMESTAMP()),0) AS delayed FROM jobs WHERE queue = ?');
        foreach (QUEUES as $q) {
            try {
                $st->execute([$q]);
                $r = $st->fetch(PDO::FETCH_ASSOC);
                $res[$q] = ['pending' => (int)$r['total'] - (int)$r['reserved'] - (int)$r['delayed'], 'delayed' => (int)$r['delayed'], 'reserved' => (int)$r['reserved']];
            } catch (Throwable) {}
        }
    }
    return ['conn' => $conn, 'queues' => $res];
}

/* ═══════════════════════════════ LOGS ═══════════════════════════════ */

function logFiles(): array {
    return [
        'laravel'      => ['Laravel app', latestLaravelLog()],
        'nginx_error'  => ['Nginx error', '/var/log/nginx/error.log'],
        'nginx_access' => ['Nginx access', '/var/log/nginx/access.log'],
        'fpm'          => ['PHP-FPM', PHP_FPM_LOG],
        'mysql'        => ['MySQL error', '/var/log/mysql/error.log'],
        'redis'        => ['Redis', '/var/log/redis/redis-server.log'],
        'supervisord'  => ['Supervisord', '/var/log/supervisor/supervisord.log'],
        'syslog'       => ['Syslog', '/var/log/syslog'],
        'auth'         => ['Auth / SSH', '/var/log/auth.log'],
        'audit'        => ['Dashboard audit', auditFile()],
    ];
}
function readLog(string $key, int $lines): array {
    $lines = max(20, min(3000, $lines));
    [$type, $name] = array_pad(explode(':', $key, 2), 2, '');
    if ($type === 'file') {
        $src = logFiles()[$name] ?? null;
        if (!$src) return ['error' => 'Unknown log'];
        $f = $src[1];
        if (!is_file($f)) return ['error' => "File not found: $f"];
        if (!is_readable($f)) return ['error' => "Permission denied: $f\nFix: sudo usermod -aG adm,systemd-journal www-data && sudo systemctl restart php8.4-fpm"];
        return ['text' => tailFile($f, $lines), 'meta' => $f . ' · ' . fmtBytes(filesize($f))];
    }
    if ($type === 'unit') {
        if (!isset(SERVICES[$name]) && $name !== 'ssh') return ['error' => 'Unknown unit'];
        $r = run('journalctl -u ' . escapeshellarg($name) . " -n $lines --no-pager -o short-iso", 15);
        return ['text' => $r['out'], 'meta' => "journalctl -u $name"];
    }
    if ($type === 'kernel') {
        return ['text' => sh("journalctl -k -n $lines --no-pager -o short-iso", 15), 'meta' => 'kernel log'];
    }
    if ($type === 'sup') {
        if (!in_array($name, array_column(supervisor()['procs'], 'name'), true)) return ['error' => 'Unknown worker'];
        $out = sh('sudo -n /usr/bin/supervisorctl tail -' . ($lines * 250) . ' ' . escapeshellarg($name), 15);
        return ['text' => implode("\n", array_slice(explode("\n", $out), -$lines)), 'meta' => "supervisorctl tail $name"];
    }
    return ['error' => 'Unknown log source'];
}

/* ═══════════════════════════════ ACTIONS ═══════════════════════════════ */

function handleAction(array $in): array {
    $a = (string)($in['action'] ?? '');
    $t = (string)($in['target'] ?? '');
    $op = (string)($in['op'] ?? '');
    $artisan = fn(string $args) => run('cd ' . escapeshellarg(LARAVEL_PATH) . ' && ' . escapeshellarg(PHP_BIN) . " artisan $args --no-interaction --no-ansi", 180);
    $title = $a; $r = null;

    switch ($a) {
        case 'svc':
            $allowed = ['restart', 'start'];
            if (in_array($t, RELOADABLE, true)) $allowed[] = 'reload';
            if (!isset(SERVICES[$t]) || !in_array($op, $allowed, true)) return bad();
            $title = ucfirst($op) . ' ' . SERVICES[$t];
            $r = run('sudo -n /usr/bin/systemctl --no-block ' . $op . ' ' . escapeshellarg($t), 20);
            if ($r['code'] === 0) $r['out'] = trim($r['out'] . "\nQueued. Give it a few seconds, then refresh to see the new status.");
            break;
        case 'sup':
            $names = array_column(supervisor()['procs'], 'name');
            $groups = array_unique(array_merge(SUPERVISOR_GROUPS, array_column(supervisor()['procs'], 'group')));
            if (!in_array($op, ['restart', 'start', 'stop'], true)) return bad();
            if ($t === 'all') $arg = 'all';
            elseif (in_array($t, $names, true)) $arg = $t;
            elseif (in_array($t, $groups, true)) $arg = $t . ':*';
            else return bad();
            $title = ucfirst($op) . ' ' . $t;
            $r = run('sudo -n /usr/bin/supervisorctl ' . $op . ' ' . escapeshellarg($arg), 90);
            break;
        case 'sup_update':
            $title = 'Supervisor reread + update';
            $r = run('sudo -n /usr/bin/supervisorctl reread && sudo -n /usr/bin/supervisorctl update', 60);
            break;
        case 'nginx_test':
            $title = 'nginx -t'; $r = run('sudo -n /usr/sbin/nginx -t', 20); break;
        case 'fpm_test':
            $title = 'php-fpm -t'; $r = run('sudo -n ' . PHP_FPM_BIN . ' -t', 20); break;
        case 'artisan':
            if (isset(ARTISAN[$t])) { $title = 'artisan ' . ARTISAN[$t][0]; $r = $artisan(ARTISAN[$t][0]); break; }
            if (in_array($t, ['queue:retry', 'queue:forget'], true) && preg_match('/^[0-9a-f\-]{36}$/i', $op)) {
                $title = "artisan $t $op"; $r = $artisan($t . ' ' . escapeshellarg($op)); break;
            }
            return bad();
        case 'journal_vacuum':
            $title = 'Vacuum systemd journal to 200 MB';
            $r = run('sudo -n /usr/bin/journalctl --vacuum-size=200M', 60); break;
        case 'reset_failed':
            $title = 'systemctl reset-failed';
            $r = run('sudo -n /usr/bin/systemctl reset-failed', 10); break;
        case 'du':
            if (!in_array($t, DU_PATHS, true)) return bad();
            $title = "Disk usage of $t";
            $r = run('sudo -n /usr/bin/du -xh --max-depth=1 ' . escapeshellarg($t) . ' 2>/dev/null | sort -rh | head -n 25', 120);
            break;
        case 'truncate_laravel_log':
            $f = latestLaravelLog();
            $title = 'Truncate ' . basename($f);
            $before = is_file($f) ? filesize($f) : 0;
            $ok = is_writable($f) && file_put_contents($f, '') !== false;
            $r = ['code' => $ok ? 0 : 1, 'out' => $ok ? 'Freed ' . fmtBytes($before) : 'Not writable: ' . $f];
            break;
        case 'mysql_kill':
            $id = (int)$t;
            $title = "KILL QUERY $id";
            try { db()?->exec('KILL QUERY ' . $id); $r = ['code' => 0, 'out' => 'Query killed.']; }
            catch (Throwable $e) { $r = ['code' => 1, 'out' => $e->getMessage()]; }
            break;
        case 'clear_cache':
            clearCache(); $title = 'Dashboard cache cleared'; $r = ['code' => 0, 'out' => 'Updates, SSL and security checks will re-run on next refresh.']; break;
        default:
            return bad();
    }
    audit(sprintf('%s → exit %d', $title, $r['code']));
    $out = $r['out'];
    if (str_contains($out, 'a password is required') || str_contains($out, 'not allowed to execute')) {
        $out .= "\n\nsudo rule missing — install server-monitor.sudoers (see setup).";
    }
    return ['ok' => $r['code'] === 0, 'title' => $title, 'out' => $out ?: '(no output)'];
}
function bad(): array { return ['ok' => false, 'title' => 'Rejected', 'out' => 'Action or target not allowed.']; }

/* ═══════════════════════════════ GATHER ═══════════════════════════════ */

$live    = liveSample(400);
$sys     = systemInfo();
$svc     = []; foreach (SERVICES as $u => $n) $svc[$u] = serviceInfo($u);
$failedU = failedUnits();
$sup     = supervisor();
$lara    = laravelInfo();
$queues  = queueSizes();
$mysql   = mysqlInfo();
$redis   = redisInfo();
$disks   = disks();
$procCpu = topProcs('cpu');
$procMem = topProcs('mem');
$ports   = listeningPorts();
$ufw     = ufwStatus();
$jAccess = journalAccess();
$ssh     = $jAccess ? sshFailures() : null;
$oom     = $jAccess ? oomEvents() : [];
$fpm     = fpmWarnings();
$ngx     = nginxErrorStats();
$ssl     = sslCerts();
$nd      = netdataAlarms();
$f2b     = serviceInfo('fail2ban');
$auditTail = is_readable(auditFile()) ? tailFile(auditFile(), 15) : '';

/* ═══════════════════════════════ HEALTH CHECKS ═══════════════════════════════ */

$issues = [];
$issue = function (string $lvl, string $msg, array $fixes = []) use (&$issues) { $issues[] = compact('lvl', 'msg', 'fixes'); };

foreach ($svc as $u => $s) {
    if (!$s['exists']) continue;
    if (!$s['active']) $issue('crit', SERVICES[$u] . " is DOWN — {$s['state']}", [btn('Start', ['action' => 'svc', 'target' => $u, 'op' => 'start']), btn('Restart', ['action' => 'svc', 'target' => $u, 'op' => 'restart']), logBtn('unit:' . $u)]);
    elseif ($s['restarts'] > 0) $issue('warn', SERVICES[$u] . " auto-restarted {$s['restarts']}× (crashing?)", [logBtn('unit:' . $u)]);
}
if ($sup['error']) $issue('crit', 'Cannot read Supervisor status: ' . mb_strimwidth($sup['error'], 0, 120, '…'));
foreach (SUPERVISOR_GROUPS as $g) {
    $ps = array_filter($sup['procs'], fn($p) => $p['group'] === $g);
    $run = count(array_filter($ps, fn($p) => $p['state'] === 'RUNNING'));
    if (!$ps && !$sup['error']) $issue('crit', "Worker group “{$g}” not found in Supervisor", [btn('Reread & update', ['action' => 'sup_update'])]);
    elseif ($ps && $run < count($ps)) $issue('crit', "Workers {$g}: only {$run}/" . count($ps) . ' running', [btn('Restart group', ['action' => 'sup', 'target' => $g, 'op' => 'restart'])]);
}
foreach ($sup['procs'] as $p) if (in_array($p['state'], ['FATAL', 'BACKOFF'], true) && !in_array($p['group'], SUPERVISOR_GROUPS, true))
    $issue('crit', "Worker {$p['name']} is {$p['state']}", [btn('Restart', ['action' => 'sup', 'target' => $p['name'], 'op' => 'restart']), logBtn('sup:' . $p['name'])]);
if ($failedU) $issue('warn', 'Failed systemd units: ' . implode(', ', $failedU), [btn('Reset failed', ['action' => 'reset_failed'])]);

$m = $live['mem'];
if ($m['pct'] >= 90) $issue('crit', "RAM at {$m['pct']}%", []);
elseif ($m['pct'] >= 80) $issue('warn', "RAM at {$m['pct']}%", []);
if ($m['swap_total'] && $m['swap_pct'] >= 50) $issue('warn', "Swap {$m['swap_pct']}% used — server is short on memory");
if (!$m['swap_total'] && $m['total'] < 4 * 1024 ** 3) $issue('warn', 'No swap configured — a small swapfile helps avoid OOM kills');
if ($live['load'][1] > $live['cores'] * 1.5) $issue('crit', "Load {$live['load'][1]} (5m) on {$live['cores']} cores");
elseif ($live['load'][1] > $live['cores']) $issue('warn', "Load {$live['load'][1]} (5m) above core count ({$live['cores']})");
if ($live['steal'] >= 10) $issue('warn', "CPU steal {$live['steal']}% — VPS host is overloaded (noisy neighbours)");
if ($live['iowait'] >= 20) $issue('warn', "High I/O wait {$live['iowait']}% — disk is a bottleneck");

foreach ($disks as $d) {
    $fix = in_array($d['mount'], DU_PATHS, true) ? [btn('What uses space?', ['action' => 'du', 'target' => $d['mount']]), btn('Vacuum journal', ['action' => 'journal_vacuum'])] : [];
    if ($d['pct'] >= 90) $issue('crit', "Disk {$d['mount']} {$d['pct']}% full (" . fmtBytes($d['avail']) . ' free)', $fix);
    elseif ($d['pct'] >= 80) $issue('warn', "Disk {$d['mount']} {$d['pct']}% full", $fix);
    if (($d['ipct'] ?? 0) >= 85) $issue('crit', "Inodes on {$d['mount']} {$d['ipct']}% used (too many small files — check sessions/cache)");
}
if ($oom) $issue('crit', count($oom) . ' out-of-memory kill(s) in the last 7 days', [logBtn('kernel:', 'Kernel log')]);
if ($fpm['count'] > 0) $issue('warn', "PHP-FPM hit pm.max_children {$fpm['count']}× recently — raise it in the pool config if RAM allows", [logBtn('file:fpm')]);
if (($ngx['timeout'] ?? 0) > 0) $issue('warn', "Nginx: {$ngx['timeout']} upstream timeouts in recent log (slow PHP requests)", [logBtn('file:nginx_error')]);
if (($ngx['crit'] ?? 0) > 0) $issue('warn', "Nginx: {$ngx['crit']} crit/alert/emerg entries in recent log", [logBtn('file:nginx_error')]);

if ($lara['found']) {
    if ($lara['debug'] && $lara['env'] === 'production') $issue('crit', 'APP_DEBUG=true in production — leaks secrets on error pages');
    if ($lara['down']) $issue('warn', 'Laravel is in maintenance mode', [btn('Bring app up', ['action' => 'artisan', 'target' => 'up'], '', ARTISAN['up'][1])]);
    if (!$lara['storage_ok']) $issue('crit', 'storage/ or bootstrap/cache is not writable by the web user');
    if (($lara['log_size'] ?? 0) > 300 * 1024 ** 2) $issue('warn', 'Laravel log is ' . fmtBytes($lara['log_size']) . ' — consider LOG_CHANNEL=daily', [btn('Truncate log', ['action' => 'truncate_laravel_log'], 'danger', 'Empty the Laravel log file?')]);
    if ($lara['errors_today'] > 0) $issue('warn', "{$lara['errors_today']} Laravel errors logged today", [logBtn('file:laravel')]);
    if ($lara['env'] === 'production' && !$lara['config_cached']) $issue('warn', 'Config is not cached in production', [btn('Run optimize', ['action' => 'artisan', 'target' => 'optimize'])]);
} else {
    $issue('warn', 'Laravel app not found at ' . LARAVEL_PATH . ' — set LARAVEL_PATH');
}
foreach ($queues['queues'] as $q => $c) if ($c['pending'] >= QUEUE_BACKLOG_WARN) $issue('warn', "Queue “{$q}” backlog: {$c['pending']} jobs waiting", [btn('Restart workers', ['action' => 'sup', 'target' => 'all', 'op' => 'restart'])]);
if (($mysql['failed_count'] ?? 0) > 0) $issue('warn', "{$mysql['failed_count']} failed jobs", [btn('Retry all', ['action' => 'artisan', 'target' => 'queue:retry-all'], '', ARTISAN['queue:retry-all'][1]), '<a class="btn ghost" href="#laravel">View</a>']);
if (isset($mysql['error']) && ($svc['mysql']['active'] ?? false)) $issue('crit', 'MySQL query failed: ' . mb_strimwidth($mysql['error'], 0, 140, '…'));
if (!empty($mysql['max_conn']) && (int)($mysql['status']['Threads_connected'] ?? 0) > 0.8 * $mysql['max_conn']) $issue('warn', 'MySQL connections near max_connections');
if (!empty($mysql['long'])) $issue('warn', count($mysql['long']) . ' MySQL queries running ≥5s', ['<a class="btn ghost" href="#mysql">View</a>']);
if (isset($redis['error']) && ($svc['redis-server']['active'] ?? false)) $issue('crit', 'Redis not reachable: ' . mb_strimwidth($redis['error'], 0, 120, '…'));
if (!isset($redis['error'])) {
    if (($redis['rdb_last_bgsave_status'] ?? 'ok') !== 'ok') $issue('crit', 'Redis last background save FAILED (disk full or permissions?)', [logBtn('file:redis')]);
    if ((int)($redis['evicted_keys'] ?? 0) > 0) $issue('warn', "Redis evicted {$redis['evicted_keys']} keys — queued jobs may be lost");
    $mx = (int)($redis['maxmemory'] ?? 0);
    if ($mx > 0 && (int)$redis['used_memory'] > 0.9 * $mx) $issue('warn', 'Redis memory above 90% of maxmemory');
    if ($mx > 0 && ($redis['maxmemory_policy'] ?? '') !== 'noeviction' && $queues['conn'] === 'redis') $issue('warn', "Redis maxmemory-policy is {$redis['maxmemory_policy']} — use noeviction when Redis holds queues");
}
if ($sys['reboot']) $issue('warn', 'Reboot required' . ($sys['reboot_pkgs'] ? ' (' . implode(', ', array_slice($sys['reboot_pkgs'], 0, 4)) . ')' : ''));
if ($sys['updates'] && $sys['updates']['security'] > 0) $issue('warn', "{$sys['updates']['security']} security updates pending — run: sudo apt update && sudo apt upgrade");
foreach ($ports as $p) if ($p['public'] && isset(SENSITIVE_PORTS[$p['port']])) $issue($ufw === 'active' ? 'warn' : 'crit', SENSITIVE_PORTS[$p['port']] . " listens on all interfaces (port {$p['port']})" . ($ufw === 'active' ? ' — make sure UFW blocks it' : ' and firewall is ' . $ufw), ['<a class="btn ghost" href="#security">View</a>']);
if ($ufw === 'inactive') $issue('warn', 'UFW firewall is inactive');
if ($ssh && $ssh['count'] > 50 && !$f2b['active']) $issue('warn', "{$ssh['count']} failed SSH logins in 24h and fail2ban is not running");
foreach ($ssl as $d => $c) {
    if (isset($c['error'])) { $issue('warn', "SSL check failed for {$d}: {$c['error']}"); continue; }
    $days = (int)floor(($c['expires'] - time()) / 86400);
    if ($days < 7) $issue('crit', "SSL for {$d} expires in {$days} days — run: sudo certbot renew");
    elseif ($days < 21) $issue('warn', "SSL for {$d} expires in {$days} days");
}
foreach ($nd['alarms'] as $a) if (in_array($a['status'], ['CRITICAL', 'WARNING'], true)) $issue($a['status'] === 'CRITICAL' ? 'crit' : 'warn', "Netdata: {$a['name']} = {$a['value']} ({$a['chart']})");
if (!$jAccess) $issue('warn', 'Web user cannot read the journal — logs/security checks limited. Add www-data to systemd-journal group.');

usort($issues, fn($a, $b) => ($a['lvl'] === 'crit' ? 0 : 1) <=> ($b['lvl'] === 'crit' ? 0 : 1));
$nCrit = count(array_filter($issues, fn($i) => $i['lvl'] === 'crit'));
$nWarn = count($issues) - $nCrit;
$overall = $nCrit ? 'crit' : ($nWarn ? 'warn' : 'ok');

/* ═══════════════════════════════ RENDER ═══════════════════════════════ */

function renderLogin(string $err): void { ?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Login · <?= h(APP_TITLE) ?></title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d1117;color:#e6edf3;font:15px system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
form{background:#161b22;border:1px solid #30363d;border-radius:14px;padding:32px;width:min(340px,90vw)}
h1{font-size:18px;margin:0 0 20px}input{width:100%;box-sizing:border-box;padding:11px 12px;border-radius:8px;border:1px solid #30363d;background:#0d1117;color:inherit;font-size:15px}
button{margin-top:14px;width:100%;padding:11px;border:0;border-radius:8px;background:#2f81f7;color:#fff;font-weight:600;font-size:15px;cursor:pointer}
.err{color:#f85149;margin-top:12px;font-size:14px}
</style></head><body>
<form method="post"><h1>🔒 <?= h(APP_TITLE) ?></h1>
<input type="password" name="password" placeholder="Password" autofocus required>
<button>Sign in</button><?php if ($err): ?><div class="err"><?= h($err) ?></div><?php endif; ?></form>
</body></html>
<?php }

$logOptions = [];
foreach (logFiles() as $k => [$label, $path]) $logOptions['file:' . $k] = 'File · ' . $label;
foreach (SERVICES as $u => $n) if ($svc[$u]['exists']) $logOptions['unit:' . $u] = 'Journal · ' . $n;
$logOptions['unit:ssh'] = 'Journal · SSH';
$logOptions['kernel:'] = 'Journal · Kernel';
foreach ($sup['procs'] as $p) $logOptions['sup:' . $p['name']] = 'Worker · ' . $p['name'];
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?= $nCrit ? "($nCrit) " : '' ?><?= h(APP_TITLE) ?></title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2129;--line:#30363d;--text:#e6edf3;--muted:#8b949e;--ok:#3fb950;--warn:#d29922;--crit:#f85149;--blue:#2f81f7;--r:12px}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--blue);text-decoration:none}
.top{position:sticky;top:0;z-index:20;display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;padding:10px 20px;background:rgba(13,17,23,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px}.brand b{font-size:16px}
.dot{width:11px;height:11px;border-radius:50%;display:inline-block}.dot.ok{background:var(--ok)}.dot.warn{background:var(--warn)}.dot.crit{background:var(--crit);box-shadow:0 0 0 4px #f8514933}
nav{display:flex;flex-wrap:wrap;gap:2px}nav a{color:var(--muted);padding:4px 8px;border-radius:6px;font-size:13px}nav a:hover{background:var(--panel2);color:var(--text)}
.right{display:flex;gap:8px;align-items:center;font-size:13px;color:var(--muted)}
main{max-width:1320px;margin:0 auto;padding:20px}
section{margin-bottom:28px;scroll-margin-top:70px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
h2 .sp{flex:1}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr))}
.grid2{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(min(520px,100%),1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:16px;min-width:0}
.card h3{margin:0 0 10px;font-size:13px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.big{font-size:30px;font-weight:700;line-height:1.1;font-variant-numeric:tabular-nums}
.big.ok{color:var(--text)}.big.warn{color:var(--warn)}.big.crit{color:var(--crit)}
.sub{color:var(--muted);font-size:12.5px;margin-top:4px;font-variant-numeric:tabular-nums}
canvas.spark{width:100%;height:46px;display:block;margin-top:10px}
.bar{height:6px;background:var(--panel2);border-radius:4px;overflow:hidden;margin-top:8px}
.bar span{display:block;height:100%;border-radius:4px}.bar .ok{background:var(--ok)}.bar .warn{background:var(--warn)}.bar .crit{background:var(--crit)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:middle}
tr:last-child td{border-bottom:0}
.tbl{overflow-x:auto}
.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.muted{color:var(--muted)}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.badge.ok{background:#3fb95022;color:var(--ok)}.badge.warn{background:#d2992222;color:var(--warn)}.badge.crit{background:#f8514922;color:var(--crit)}.badge.off{background:#8b949e22;color:var(--muted)}
.btn{display:inline-block;background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:7px;padding:5px 11px;font-size:12.5px;cursor:pointer;margin:2px 4px 2px 0;white-space:nowrap;font-family:inherit}
.btn:hover{border-color:var(--blue)}.btn:disabled{opacity:.5;cursor:wait}
.btn.primary{background:var(--blue);border-color:var(--blue);color:#fff}
.btn.danger{border-color:#f8514966;color:var(--crit)}
.btn.ghost{background:transparent}
.issue{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:10px 14px;border-radius:10px;margin-bottom:8px;border:1px solid}
.issue.crit{background:#f8514912;border-color:#f8514955}.issue.warn{background:#d2992212;border-color:#d2992255}
.issue .ico{font-weight:800;width:18px;text-align:center}.issue.crit .ico{color:var(--crit)}.issue.warn .ico{color:var(--warn)}
.issue .msg{flex:1;min-width:220px}
.allgood{padding:16px;border-radius:10px;background:#3fb95014;border:1px solid #3fb95055;color:var(--ok);font-weight:600}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:13px}.kv dt{color:var(--muted)}.kv dd{margin:0;word-break:break-word}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.logbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
select,input[type=text]{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:7px;padding:6px 9px;font:inherit;font-size:13px}
#log-out{background:#010409;border:1px solid var(--line);border-radius:10px;padding:12px;height:460px;overflow:auto;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
#log-out .err{color:#ff7b72}#log-out .warn{color:#e3b341}
pre.box{background:#010409;border:1px solid var(--line);border-radius:10px;padding:12px;font:12px/1.5 ui-monospace,monospace;white-space:pre-wrap;word-break:break-all;max-height:260px;overflow:auto;margin:0}
.modal{position:fixed;inset:0;background:#000a;display:none;align-items:center;justify-content:center;z-index:50;padding:16px}
.modal.open{display:flex}
.modal .card{width:min(820px,100%);max-height:85vh;display:flex;flex-direction:column}
.modal pre{flex:1;overflow:auto;max-height:none}
.modal .head{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:10px}
.modal .head b{font-size:15px}.modal .head b.ok{color:var(--ok)}.modal .head b.crit{color:var(--crit)}
details summary{cursor:pointer;color:var(--muted);font-size:12px}
@media (max-width:640px){main{padding:12px}.top{padding:10px 12px}nav{display:none}}
</style>
</head>
<body>

<header class="top">
  <div class="brand">
    <span class="dot <?= $overall ?>" title="<?= $nCrit ?> critical, <?= $nWarn ?> warnings"></span>
    <b><?= h(APP_TITLE) ?></b>
    <span class="muted"><?= h($sys['host']) ?> · up <span id="uptime"><?= fmtDur($sys['uptime']) ?></span></span>
  </div>
  <nav>
    <a href="#health">Health</a><a href="#services">Services</a><a href="#workers">Workers</a><a href="#laravel">Laravel</a>
    <a href="#mysql">MySQL</a><a href="#redis">Redis</a><a href="#disks">Disks</a><a href="#procs">Processes</a>
    <a href="#security">Security</a><a href="#netdata">Netdata</a><a href="#logs">Logs</a><a href="#tools">Tools</a>
  </nav>
  <div class="right">
    <span id="live-dot" class="muted">● live</span>
    <label><input type="checkbox" id="auto"> auto 60s</label>
    <button class="btn" onclick="location.reload()">Refresh</button>
    <a class="btn ghost" href="?logout=1">Logout</a>
  </div>
</header>

<main>

<!-- ───────── HEALTH ───────── -->
<section id="health">
  <h2>Health
    <?= $nCrit ? badge('crit', "$nCrit critical") : '' ?>
    <?= $nWarn ? badge('warn', "$nWarn warnings") : '' ?>
    <span class="sp"></span><span class="muted" style="text-transform:none;letter-spacing:0"><?= h($sys['time']) ?></span>
  </h2>
  <?php if (!$issues): ?>
    <div class="allgood">✓ Everything looks healthy</div>
  <?php else: foreach ($issues as $i): ?>
    <div class="issue <?= $i['lvl'] ?>">
      <span class="ico"><?= $i['lvl'] === 'crit' ? '✖' : '!' ?></span>
      <span class="msg"><?= h($i['msg']) ?></span>
      <span><?= implode('', $i['fixes']) ?></span>
    </div>
  <?php endforeach; endif; ?>
</section>

<!-- ───────── LIVE ───────── -->
<section id="live">
  <h2>Live</h2>
  <div class="grid">
    <div class="card"><h3>CPU</h3>
      <div class="big" id="cpu-val"><?= $live['cpu'] ?>%</div>
      <div class="sub" id="cpu-break">user <?= $live['user'] ?>% · sys <?= $live['system'] ?>% · iowait <?= $live['iowait'] ?>% · steal <?= $live['steal'] ?>%</div>
      <canvas class="spark" id="cpu-spark"></canvas>
    </div>
    <div class="card"><h3>Load average</h3>
      <div class="big" id="load-val"><?= $live['load'][0] ?></div>
      <div class="sub" id="load-sub">5m <?= $live['load'][1] ?> · 15m <?= $live['load'][2] ?> · <?= $live['cores'] ?> cores</div>
      <canvas class="spark" id="load-spark"></canvas>
    </div>
    <div class="card"><h3>Memory</h3>
      <div class="big" id="mem-val"><?= $m['pct'] ?>%</div>
      <div class="sub" id="mem-sub"><?= fmtBytes($m['used']) ?> / <?= fmtBytes($m['total']) ?> · swap <?= $m['swap_total'] ? fmtBytes($m['swap_used']) . ' / ' . fmtBytes($m['swap_total']) : 'none' ?></div>
      <canvas class="spark" id="mem-spark"></canvas>
    </div>
    <div class="card"><h3>Network</h3>
      <div class="big" id="net-val" style="font-size:22px">↓ <?= fmtBytes($live['rx']) ?>/s</div>
      <div class="sub" id="net-sub">↑ <?= fmtBytes($live['tx']) ?>/s</div>
      <canvas class="spark" id="net-spark"></canvas>
    </div>
  </div>
</section>

<!-- ───────── SYSTEM ───────── -->
<section id="system">
  <h2>System</h2>
  <div class="card">
    <dl class="kv">
      <dt>Hostname</dt><dd><?= h($sys['host']) ?> <?= $sys['ip'] ? '<span class="muted">(' . h($sys['ip']) . ')</span>' : '' ?></dd>
      <dt>OS / Kernel</dt><dd><?= h($sys['os']) ?> · <?= h($sys['kernel']) ?> · <?= h($sys['virt']) ?></dd>
      <dt>CPU</dt><dd><?= h($sys['cpu_model']) ?> · <?= $sys['cores'] ?> vCPU</dd>
      <dt>Uptime</dt><dd><?= fmtDur($sys['uptime']) ?></dd>
      <dt>PHP (web)</dt><dd><?= h($sys['php']) ?> · <?= h(php_sapi_name()) ?> · user <?= h(get_current_user()) ?>/<?= h(posix_getpwuid(posix_geteuid())['name'] ?? '?') ?></dd>
      <dt>Updates</dt><dd><?php if ($sys['updates'] === null): ?><span class="muted">unknown</span><?php else: ?>
        <?= $sys['updates']['all'] ?> pending (<?= $sys['updates']['security'] ?> security) <?= $sys['updates']['security'] ? badge('warn', 'security') : badge('ok', 'ok') ?><?php endif; ?></dd>
      <dt>Reboot</dt><dd><?= $sys['reboot'] ? badge('warn', 'required') : badge('ok', 'not needed') ?></dd>
    </dl>
  </div>
</section>

<!-- ───────── SERVICES ───────── -->
<section id="services">
  <h2>Services <span class="sp"></span><?= btn('Test Nginx config', ['action' => 'nginx_test']) ?><?= btn('Test PHP-FPM config', ['action' => 'fpm_test']) ?></h2>
  <div class="card tbl">
    <table>
      <tr><th>Service</th><th>Status</th><th>Up for</th><th>PID</th><th>Memory</th><th>Tasks</th><th>Restarts</th><th>Boot</th><th>Actions</th></tr>
      <?php foreach ($svc as $u => $s): ?>
      <tr>
        <td><b><?= h(SERVICES[$u]) ?></b> <span class="muted mono"><?= h($u) ?></span></td>
        <td><?= !$s['exists'] ? badge('off', 'not installed') : ($s['active'] ? badge('ok', '● UP') : badge('crit', '● DOWN')) ?>
            <?php if ($s['exists'] && !$s['active']): ?><div class="muted mono"><?= h($s['state']) ?></div><?php endif; ?></td>
        <td class="num"><?= fmtDur($s['since']) ?></td>
        <td class="num mono"><?= $s['pid'] ?: '—' ?></td>
        <td class="num"><?= fmtBytes($s['mem']) ?></td>
        <td class="num"><?= $s['tasks'] ?? '—' ?></td>
        <td class="num"><?= $s['restarts'] ? badge('warn', (string)$s['restarts']) : '0' ?></td>
        <td><?= $s['enabled'] === 'enabled' ? '<span class="muted">enabled</span>' : badge('warn', $s['enabled'] ?: '?') ?></td>
        <td><?php if ($s['exists']): ?>
          <?= $s['active'] ? '' : btn('Start', ['action' => 'svc', 'target' => $u, 'op' => 'start'], 'primary') ?>
          <?= btn('Restart', ['action' => 'svc', 'target' => $u, 'op' => 'restart'], '', 'Restart ' . SERVICES[$u] . '?') ?>
          <?= in_array($u, RELOADABLE, true) ? btn('Reload', ['action' => 'svc', 'target' => $u, 'op' => 'reload']) : '' ?>
          <?= logBtn('unit:' . $u) ?>
        <?php endif; ?></td>
      </tr>
      <?php endforeach; ?>
    </table>
  </div>
</section>

<!-- ───────── WORKERS ───────── -->
<section id="workers">
  <h2>Queue workers (Supervisor) <span class="sp"></span>
    <?= btn('Restart all workers', ['action' => 'sup', 'target' => 'all', 'op' => 'restart'], '', 'Restart ALL supervisor programs?') ?>
    <?= btn('Reread & update', ['action' => 'sup_update']) ?>
  </h2>
  <?php if ($sup['error']): ?><div class="issue crit"><span class="ico">✖</span><span class="msg mono"><?= h($sup['error']) ?></span></div><?php endif; ?>
  <div class="grid" style="margin-bottom:12px">
    <?php foreach (SUPERVISOR_GROUPS as $g):
      $ps = array_filter($sup['procs'], fn($p) => $p['group'] === $g);
      $run = count(array_filter($ps, fn($p) => $p['state'] === 'RUNNING'));
      $l = !$ps ? 'crit' : ($run === count($ps) ? 'ok' : 'crit'); ?>
      <div class="card"><h3><?= h($g) ?></h3>
        <div class="big <?= $l ?>"><?= $run ?>/<?= count($ps) ?></div><div class="sub">processes running</div>
        <div style="margin-top:10px">
          <?= btn('Restart', ['action' => 'sup', 'target' => $g, 'op' => 'restart']) ?>
          <?= btn('Stop', ['action' => 'sup', 'target' => $g, 'op' => 'stop'], 'danger', "Stop all {$g} workers? Jobs on this queue will stop processing.") ?>
          <?= btn('Start', ['action' => 'sup', 'target' => $g, 'op' => 'start']) ?>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
  <?php if ($sup['procs']): ?>
  <div class="card tbl">
    <table>
      <tr><th>Process</th><th>State</th><th>Details</th><th>Actions</th></tr>
      <?php foreach ($sup['procs'] as $p): ?>
      <tr>
        <td class="mono"><?= h($p['name']) ?></td>
        <td><?= badge($p['state'] === 'RUNNING' ? 'ok' : (in_array($p['state'], ['STARTING', 'STOPPED']) ? 'warn' : 'crit'), $p['state']) ?></td>
        <td class="muted mono"><?= h($p['info']) ?></td>
        <td><?= btn('Restart', ['action' => 'sup', 'target' => $p['name'], 'op' => 'restart']) ?><?= logBtn('sup:' . $p['name']) ?></td>
      </tr>
      <?php endforeach; ?>
    </table>
  </div>
  <?php endif; ?>
</section>

<!-- ───────── LARAVEL ───────── -->
<section id="laravel">
  <h2>Laravel & queues</h2>
  <div class="chips">
    <?= badge($lara['env'] === 'production' ? 'ok' : 'warn', 'env: ' . $lara['env']) ?>
    <?= badge($lara['debug'] ? ($lara['env'] === 'production' ? 'crit' : 'warn') : 'ok', 'debug: ' . ($lara['debug'] ? 'ON' : 'off')) ?>
    <?= badge($lara['down'] ? 'warn' : 'ok', $lara['down'] ? 'maintenance mode' : 'live') ?>
    <?= badge($lara['config_cached'] ? 'ok' : 'off', 'config ' . ($lara['config_cached'] ? 'cached' : 'not cached')) ?>
    <?= badge($lara['routes_cached'] ? 'ok' : 'off', 'routes ' . ($lara['routes_cached'] ? 'cached' : 'not cached')) ?>
    <?= badge($lara['storage_ok'] ? 'ok' : 'crit', 'storage ' . ($lara['storage_ok'] ? 'writable' : 'NOT writable')) ?>
    <?= badge('off', 'queue: ' . $lara['queue']) ?><?= badge('off', 'cache: ' . $lara['cache']) ?><?= badge('off', 'session: ' . $lara['session']) ?>
    <?= badge($lara['errors_today'] ? 'warn' : 'ok', $lara['errors_today'] . ' errors today') ?>
    <?= badge('off', 'log ' . fmtBytes($lara['log_size'])) ?>
  </div>
  <div class="grid2">
    <div class="card">
      <h3>Queue backlog <span class="muted" style="text-transform:none">(<?= h($queues['conn']) ?>)</span></h3>
      <?php if (!$queues['queues']): ?>
        <div class="muted">No queue data (connection “<?= h($queues['conn']) ?>” — redis and database are supported).</div>
      <?php else: ?>
      <table><tr><th>Queue</th><th>Waiting</th><th>Delayed</th><th>Processing</th></tr>
        <?php foreach ($queues['queues'] as $q => $c): ?>
        <tr><td><b><?= h($q) ?></b></td>
          <td class="num"><?= $c['pending'] >= QUEUE_BACKLOG_WARN ? badge('warn', (string)$c['pending']) : $c['pending'] ?></td>
          <td class="num"><?= $c['delayed'] ?></td><td class="num"><?= $c['reserved'] ?></td></tr>
        <?php endforeach; ?>
      </table>
      <?php endif; ?>
      <div style="margin-top:12px">
        <?php foreach (['queue:restart', 'optimize:clear', 'optimize', 'migrate:status', 'schedule:list', 'about'] as $k) echo btn('artisan ' . ARTISAN[$k][0], ['action' => 'artisan', 'target' => $k], '', ARTISAN[$k][1]); ?>
        <?= logBtn('file:laravel', 'Laravel log') ?>
      </div>
    </div>
    <div class="card">
      <h3>Failed jobs <?= ($mysql['failed_count'] ?? null) === null ? '' : '(' . $mysql['failed_count'] . ')' ?></h3>
      <?php if (($mysql['failed_count'] ?? null) === null): ?>
        <div class="muted">failed_jobs table not readable.</div>
      <?php elseif (!$mysql['failed_count']): ?>
        <div class="allgood">✓ No failed jobs</div>
      <?php else: ?>
        <div style="margin-bottom:10px">
          <?= btn('Retry all', ['action' => 'artisan', 'target' => 'queue:retry-all'], 'primary', ARTISAN['queue:retry-all'][1]) ?>
          <?= btn('Delete all', ['action' => 'artisan', 'target' => 'queue:flush'], 'danger', ARTISAN['queue:flush'][1]) ?>
        </div>
        <div class="tbl" style="max-height:340px;overflow:auto">
        <table><tr><th>Job</th><th>Failed</th><th></th></tr>
          <?php foreach ($mysql['failed'] as $f):
            $job = preg_match('/"displayName":"([^"]+)"/', (string)$f['payload'], $jm) ? stripslashes($jm[1]) : '?'; ?>
          <tr><td><b><?= h($job) ?></b> <span class="muted">on <?= h($f['queue']) ?></span>
              <details><summary><?= h(mb_strimwidth(strtok((string)$f['exception'], "\n"), 0, 90, '…')) ?></summary><pre class="box"><?= h($f['exception']) ?></pre></details></td>
            <td class="num muted"><?= h($f['failed_at']) ?></td>
            <td><?= btn('Retry', ['action' => 'artisan', 'target' => 'queue:retry', 'op' => $f['uuid']]) ?><?= btn('Forget', ['action' => 'artisan', 'target' => 'queue:forget', 'op' => $f['uuid']], 'danger', 'Delete this failed job?') ?></td></tr>
          <?php endforeach; ?>
        </table></div>
      <?php endif; ?>
    </div>
  </div>
</section>

<!-- ───────── MYSQL ───────── -->
<section id="mysql">
  <h2>MySQL <?= logBtn('file:mysql', 'Error log') ?></h2>
  <?php if (isset($mysql['error']) && empty($mysql['status'])): ?>
    <div class="issue crit"><span class="ico">✖</span><span class="msg mono"><?= h($mysql['error']) ?></span></div>
  <?php else: $st = $mysql['status'];
    $conn = (int)($st['Threads_connected'] ?? 0); $cpct = $mysql['max_conn'] ? $conn / $mysql['max_conn'] * 100 : 0;
    $bpT = (int)($st['Innodb_buffer_pool_pages_total'] ?? 0); $bpPct = $bpT ? (1 - (int)$st['Innodb_buffer_pool_pages_free'] / $bpT) * 100 : 0;
    $up = max(1, (int)($st['Uptime'] ?? 1)); ?>
  <div class="grid" style="margin-bottom:12px">
    <div class="card"><h3>Connections</h3><div class="big <?= lvl($cpct, 70, 85) ?>"><?= $conn ?></div>
      <div class="sub">of <?= $mysql['max_conn'] ?> max · peak <?= h($st['Max_used_connections'] ?? '?') ?> · running <?= h($st['Threads_running'] ?? '?') ?></div><?= bar($cpct, lvl($cpct, 70, 85)) ?></div>
    <div class="card"><h3>Queries</h3><div class="big"><?= round((int)($st['Questions'] ?? 0) / $up, 1) ?>/s</div>
      <div class="sub">avg since start · slow: <?= h($st['Slow_queries'] ?? '?') ?> · aborted connects: <?= h($st['Aborted_connects'] ?? '?') ?></div></div>
    <div class="card"><h3>Database “<?= h($mysql['db']) ?>”</h3><div class="big"><?= fmtBytes($mysql['size']) ?></div>
      <div class="sub"><?= h($mysql['version']) ?> · up <?= fmtDur($up) ?></div></div>
    <div class="card"><h3>InnoDB buffer pool</h3><div class="big"><?= round($bpPct) ?>%</div>
      <div class="sub">used of <?= fmtBytes($bpT * 16384) ?></div><?= bar($bpPct, 'ok') ?></div>
  </div>
  <div class="grid2">
    <div class="card tbl"><h3>Largest tables</h3>
      <table><tr><th>Table</th><th>Rows (est.)</th><th>Size</th></tr>
        <?php foreach ($mysql['tables'] as $t): ?><tr><td class="mono"><?= h($t['n']) ?></td><td class="num"><?= number_format((int)$t['r']) ?></td><td class="num"><?= fmtBytes((int)$t['s']) ?></td></tr><?php endforeach; ?>
      </table></div>
    <div class="card tbl"><h3>Queries running ≥ 5s</h3>
      <?php if (!$mysql['long']): ?><div class="muted">None 👍</div><?php else: ?>
      <table><tr><th>ID</th><th>Time</th><th>Query</th><th></th></tr>
        <?php foreach ($mysql['long'] as $q): ?><tr><td class="mono"><?= (int)$q['id'] ?></td><td class="num"><?= (int)$q['t'] ?>s</td>
          <td class="mono"><?= h(mb_strimwidth((string)$q['q'], 0, 140, '…')) ?><div class="muted"><?= h($q['st']) ?></div></td>
          <td><?= btn('Kill', ['action' => 'mysql_kill', 'target' => (string)$q['id']], 'danger', 'Kill this query?') ?></td></tr><?php endforeach; ?>
      </table><?php endif; ?></div>
  </div>
  <?php endif; ?>
</section>

<!-- ───────── REDIS ───────── -->
<section id="redis">
  <h2>Redis <?= logBtn('file:redis', 'Log') ?></h2>
  <?php if (isset($redis['error'])): ?>
    <div class="issue crit"><span class="ico">✖</span><span class="msg mono"><?= h($redis['error']) ?></span></div>
  <?php else:
    $hits = (int)$redis['keyspace_hits']; $miss = (int)$redis['keyspace_misses'];
    $mx = (int)$redis['maxmemory']; $rpct = $mx ? (int)$redis['used_memory'] / $mx * 100 : 0; ?>
  <div class="grid">
    <div class="card"><h3>Memory</h3><div class="big"><?= h($redis['used_memory_human']) ?></div>
      <div class="sub">max <?= $mx ? h($redis['maxmemory_human']) : 'unlimited' ?> · policy <?= h($redis['maxmemory_policy'] ?? '?') ?> · frag <?= h($redis['mem_fragmentation_ratio'] ?? '?') ?></div>
      <?= $mx ? bar($rpct, lvl($rpct, 75, 90)) : '' ?></div>
    <div class="card"><h3>Traffic</h3><div class="big"><?= h($redis['instantaneous_ops_per_sec']) ?> ops/s</div>
      <div class="sub">hit rate <?= ($hits + $miss) ? round($hits / ($hits + $miss) * 100, 1) . '%' : '—' ?> · clients <?= h($redis['connected_clients']) ?> (blocked <?= h($redis['blocked_clients'] ?? 0) ?>)</div></div>
    <div class="card"><h3>Keys</h3><div class="big"><?= number_format($redis['_keys']) ?></div>
      <div class="sub">evicted <?= h($redis['evicted_keys']) ?> · expired <?= h($redis['expired_keys']) ?></div></div>
    <div class="card"><h3>Server</h3><div class="big" style="font-size:20px">v<?= h($redis['redis_version']) ?></div>
      <div class="sub">up <?= fmtDur((int)$redis['uptime_in_seconds']) ?> · role <?= h($redis['role']) ?> · last save <?= ($redis['rdb_last_bgsave_status'] ?? '') === 'ok' ? 'ok' : '<b style="color:var(--crit)">FAILED</b>' ?> · AOF <?= ($redis['aof_enabled'] ?? '0') === '1' ? 'on' : 'off' ?></div></div>
  </div>
  <?php endif; ?>
</section>

<!-- ───────── DISKS ───────── -->
<section id="disks">
  <h2>Disks <span class="sp"></span><?= btn('Vacuum journal (keep 200MB)', ['action' => 'journal_vacuum'], '', 'Delete old system journal logs down to 200 MB?') ?>
    <?= btn('Truncate Laravel log', ['action' => 'truncate_laravel_log'], 'danger', 'Empty the current Laravel log file?') ?></h2>
  <div class="card tbl">
    <table><tr><th>Mount</th><th>Device</th><th>Used</th><th style="width:30%">Usage</th><th>Free</th><th>Inodes</th><th></th></tr>
      <?php foreach ($disks as $d): $l = lvl($d['pct'], 80, 90); ?>
      <tr><td><b><?= h($d['mount']) ?></b></td><td class="muted mono"><?= h($d['fs']) ?> · <?= h($d['type']) ?></td>
        <td class="num"><?= fmtBytes($d['used']) ?> / <?= fmtBytes($d['size']) ?></td>
        <td><span class="num"><?= $d['pct'] ?>%</span><?= bar($d['pct'], $l) ?></td>
        <td class="num"><?= fmtBytes($d['avail']) ?></td>
        <td class="num"><?= $d['ipct'] === null ? '—' : $d['ipct'] . '%' ?></td>
        <td><?= in_array($d['mount'], DU_PATHS, true) ? btn('What uses space?', ['action' => 'du', 'target' => $d['mount']]) : '' ?></td></tr>
      <?php endforeach; ?>
    </table>
    <div style="margin-top:10px"><?php foreach (array_diff(DU_PATHS, array_column($disks, 'mount')) as $p) echo btn("du $p", ['action' => 'du', 'target' => $p]); ?></div>
  </div>
</section>

<!-- ───────── PROCESSES ───────── -->
<section id="procs">
  <h2>Top processes</h2>
  <div class="grid2">
    <?php foreach (['By CPU' => $procCpu, 'By memory' => $procMem] as $title => $list): ?>
    <div class="card tbl"><h3><?= $title ?></h3>
      <table><tr><th>PID</th><th>User</th><th>CPU</th><th>RAM</th><th>Age</th><th>Command</th></tr>
        <?php foreach ($list as $p): ?><tr><td class="mono"><?= h($p['pid']) ?></td><td><?= h($p['user']) ?></td>
          <td class="num"><?= h($p['cpu']) ?>%</td><td class="num"><?= fmtBytes($p['rss']) ?></td><td class="num muted"><?= fmtDur($p['age']) ?></td>
          <td class="mono" title="<?= h($p['cmd']) ?>"><?= h(mb_strimwidth($p['cmd'], 0, 60, '…')) ?></td></tr><?php endforeach; ?>
      </table></div>
    <?php endforeach; ?>
  </div>
</section>

<!-- ───────── SECURITY ───────── -->
<section id="security">
  <h2>Network & security</h2>
  <div class="grid2">
    <div class="card tbl"><h3>Listening ports · firewall <?= badge($ufw === 'active' ? 'ok' : ($ufw === 'inactive' ? 'crit' : 'off'), 'UFW ' . $ufw) ?></h3>
      <table><tr><th>Port</th><th>Proto</th><th>Bound to</th><th>Process</th></tr>
        <?php foreach ($ports as $p): $sens = $p['public'] && isset(SENSITIVE_PORTS[$p['port']]); ?>
        <tr><td class="num"><b><?= $p['port'] ?></b></td><td class="muted"><?= h($p['proto']) ?></td>
          <td><?= $p['public'] ? badge($sens ? 'crit' : 'warn', 'public ' . $p['addr']) : '<span class="muted mono">' . h($p['addr']) . '</span>' ?></td>
          <td class="mono"><?= h($p['proc'] ?: (SENSITIVE_PORTS[$p['port']] ?? '')) ?></td></tr>
        <?php endforeach; ?>
      </table></div>
    <div class="card">
      <h3>SSH</h3>
      <?php if ($ssh === null): ?><div class="muted">Journal not readable by web user.</div><?php else: ?>
        <div class="big <?= $ssh['count'] > 50 ? 'warn' : 'ok' ?>"><?= $ssh['count'] ?></div>
        <div class="sub">failed login attempts in 24h · fail2ban <?= $f2b['exists'] ? ($f2b['active'] ? badge('ok', 'active') : badge('crit', 'stopped')) : badge('warn', 'not installed') ?></div>
        <?php if ($ssh['top']): ?><table style="margin-top:10px"><tr><th>Top attacking IPs</th><th>Attempts</th></tr>
          <?php foreach ($ssh['top'] as $aip => $n): ?><tr><td class="mono"><?= h($aip) ?></td><td class="num"><?= $n ?></td></tr><?php endforeach; ?></table><?php endif; ?>
      <?php endif; ?>
      <div style="margin-top:10px"><?= logBtn('file:auth', 'Auth log') ?><?= logBtn('unit:ssh', 'SSH journal') ?></div>
      <h3 style="margin-top:18px">Recent logins</h3>
      <pre class="box"><?= h(sh('last -n 6 -a 2>/dev/null | head -n 6', 5) ?: 'n/a') ?></pre>
      <h3 style="margin-top:18px">OOM kills (7 days)</h3>
      <?= $oom ? '<pre class="box">' . h(implode("\n", $oom)) . '</pre>' : '<div class="muted">None 👍</div>' ?>
    </div>
  </div>
  <?php if ($ssl): ?>
  <div class="card tbl" style="margin-top:12px"><h3>SSL certificates</h3>
    <table><tr><th>Domain</th><th>Issuer</th><th>Expires</th><th>Days left</th></tr>
      <?php foreach ($ssl as $d => $c): ?>
      <tr><td><b><?= h($d) ?></b></td>
        <?php if (isset($c['error'])): ?><td colspan="3"><?= badge('warn', $c['error']) ?></td>
        <?php else: $days = (int)floor(($c['expires'] - time()) / 86400); ?>
          <td class="muted"><?= h($c['issuer']) ?></td><td class="num"><?= date('Y-m-d', $c['expires']) ?></td>
          <td><?= badge($days < 7 ? 'crit' : ($days < 21 ? 'warn' : 'ok'), "$days days") ?></td>
        <?php endif; ?></tr>
      <?php endforeach; ?>
    </table></div>
  <?php endif; ?>
</section>

<!-- ───────── NETDATA ───────── -->
<section id="netdata">
  <h2>Netdata alarms <span class="sp"></span><?= NETDATA_LINK ? '<a class="btn primary" target="_blank" rel="noopener" href="' . h(NETDATA_LINK) . '">Open Netdata ↗</a>' : '' ?></h2>
  <div class="card">
    <?php if (isset($nd['error'])): ?><div class="muted"><?= h($nd['error']) ?></div>
    <?php elseif (!$nd['alarms']): ?><div class="allgood">✓ No active Netdata alarms</div>
    <?php else: ?>
    <div class="tbl"><table><tr><th>Status</th><th>Alarm</th><th>Value</th><th>Chart</th><th>Since</th></tr>
      <?php foreach ($nd['alarms'] as $a): ?>
      <tr><td><?= badge($a['status'] === 'CRITICAL' ? 'crit' : ($a['status'] === 'WARNING' ? 'warn' : 'off'), $a['status']) ?></td>
        <td><b><?= h($a['name']) ?></b><div class="muted"><?= h(strip_tags((string)$a['info'])) ?></div></td>
        <td class="num"><?= h($a['value']) ?></td><td class="mono muted"><?= h($a['chart']) ?></td>
        <td class="num muted"><?= $a['since'] ? fmtDur(time() - $a['since']) . ' ago' : '—' ?></td></tr>
      <?php endforeach; ?>
    </table></div>
    <?php endif; ?>
  </div>
</section>

<!-- ───────── LOGS ───────── -->
<section id="logs">
  <h2>Logs</h2>
  <div class="card">
    <div class="logbar">
      <select id="log-src"><?php foreach ($logOptions as $k => $label): ?><option value="<?= h($k) ?>"><?= h($label) ?></option><?php endforeach; ?></select>
      <select id="log-lines"><option>100</option><option selected>300</option><option>1000</option><option>3000</option></select>
      <input type="text" id="log-filter" placeholder="Filter text…">
      <label class="muted"><input type="checkbox" id="log-err"> errors only</label>
      <button class="btn primary" id="log-load">Load</button>
      <span class="muted mono" id="log-meta"></span>
    </div>
    <div id="log-out"><span class="muted">Pick a log and press Load.</span></div>
  </div>
</section>

<!-- ───────── TOOLS ───────── -->
<section id="tools">
  <h2>Tools</h2>
  <div class="grid2">
    <div class="card">
      <h3>Quick fixes</h3>
      <?= btn('Test Nginx config', ['action' => 'nginx_test']) ?>
      <?= btn('Test PHP-FPM config', ['action' => 'fpm_test']) ?>
      <?= btn('Reload Nginx', ['action' => 'svc', 'target' => 'nginx', 'op' => 'reload']) ?>
      <?= btn('Reload PHP-FPM', ['action' => 'svc', 'target' => 'php8.4-fpm', 'op' => 'reload']) ?>
      <?= btn('Restart all workers', ['action' => 'sup', 'target' => 'all', 'op' => 'restart'], '', 'Restart ALL supervisor programs?') ?>
      <?= btn('artisan queue:restart', ['action' => 'artisan', 'target' => 'queue:restart']) ?>
      <?= btn('artisan optimize:clear', ['action' => 'artisan', 'target' => 'optimize:clear']) ?>
      <?= btn('artisan optimize', ['action' => 'artisan', 'target' => 'optimize']) ?>
      <?= btn('Vacuum journal', ['action' => 'journal_vacuum'], '', 'Delete old journal logs down to 200 MB?') ?>
      <?= btn('Reset failed units', ['action' => 'reset_failed']) ?>
      <?= btn('Re-run cached checks', ['action' => 'clear_cache']) ?>
      <p class="muted" style="margin:12px 0 0;font-size:12.5px">After a deploy: <b>optimize</b> → <b>queue:restart</b>. 502 errors: check PHP-FPM, then reload it. Disk full: “What uses space?”, vacuum journal, truncate Laravel log.</p>
    </div>
    <div class="card"><h3>Action audit log</h3><pre class="box"><?= h($auditTail ?: 'No actions yet.') ?></pre></div>
  </div>
</section>

</main>

<div class="modal" id="modal"><div class="card">
  <div class="head"><b id="modal-title"></b><span><button class="btn" onclick="location.reload()">Refresh page</button><button class="btn" id="modal-close">Close</button></span></div>
  <pre class="box" id="modal-out"></pre>
</div></div>

<script>
const CSRF = <?= json_encode($_SESSION['csrf']) ?>;
const $ = s => document.querySelector(s);
const fmtB = b => { const u=['B','KB','MB','GB','TB']; let i=0; while(b>=1024&&i<u.length-1){b/=1024;i++;} return (i?b.toFixed(1):Math.round(b))+' '+u[i]; };
const fmtDur = s => { s=Math.floor(s); const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60); return d?`${d}d ${h}h`:h?`${h}h ${m}m`:`${m}m`; };
const lv = (v,w,c) => v>=c?'crit':v>=w?'warn':'ok';
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const N = 60, hist = {cpu:[], load:[], mem:[], rx:[], tx:[]};
const push = (k,v) => { hist[k].push(v); if (hist[k].length > N) hist[k].shift(); };

function spark(id, series, max) {
  const c = document.getElementById(id); if (!c) return;
  const dpr = devicePixelRatio || 1, w = c.clientWidth, h = c.clientHeight;
  c.width = w*dpr; c.height = h*dpr;
  const g = c.getContext('2d'); g.scale(dpr,dpr); g.clearRect(0,0,w,h);
  const m = max || Math.max(1, ...series.flatMap(s => s.data));
  series.forEach(s => {
    if (s.data.length < 2) return;
    const step = w/(N-1), off = w - (s.data.length-1)*step;
    g.beginPath();
    s.data.forEach((v,i) => { const x = off+i*step, y = h-2-(v/m)*(h-4); i ? g.lineTo(x,y) : g.moveTo(x,y); });
    g.strokeStyle = s.color; g.lineWidth = 1.6; g.stroke();
    g.lineTo(w,h); g.lineTo(off,h); g.closePath(); g.globalAlpha = .12; g.fillStyle = s.color; g.fill(); g.globalAlpha = 1;
  });
}

async function live() {
  try {
    const r = await fetch('?api=live', {cache:'no-store'});
    if (r.status === 401) return location.reload();
    const d = await r.json();
    push('cpu', d.cpu); push('load', d.load[0]); push('mem', d.mem.pct); push('rx', d.rx); push('tx', d.tx);
    const cv = $('#cpu-val'); cv.textContent = d.cpu + '%'; cv.className = 'big ' + lv(d.cpu, 75, 90);
    $('#cpu-break').textContent = `user ${d.user}% · sys ${d.system}% · iowait ${d.iowait}% · steal ${d.steal}%`;
    const lvv = $('#load-val'); lvv.textContent = d.load[0]; lvv.className = 'big ' + lv(d.load[0]/d.cores, 1, 1.5);
    $('#load-sub').textContent = `5m ${d.load[1]} · 15m ${d.load[2]} · ${d.cores} cores`;
    const mv = $('#mem-val'); mv.textContent = d.mem.pct + '%'; mv.className = 'big ' + lv(d.mem.pct, 80, 90);
    $('#mem-sub').textContent = `${fmtB(d.mem.used)} / ${fmtB(d.mem.total)} · swap ${d.mem.swap_total ? fmtB(d.mem.swap_used)+' / '+fmtB(d.mem.swap_total) : 'none'}`;
    $('#net-val').textContent = '↓ ' + fmtB(d.rx) + '/s'; $('#net-sub').textContent = '↑ ' + fmtB(d.tx) + '/s';
    $('#uptime').textContent = fmtDur(d.uptime);
    spark('cpu-spark', [{data:hist.cpu, color:css('--blue')}], 100);
    spark('load-spark', [{data:hist.load, color:'#a371f7'}], Math.max(d.cores, ...hist.load));
    spark('mem-spark', [{data:hist.mem, color:css('--ok')}], 100);
    spark('net-spark', [{data:hist.rx, color:css('--blue')}, {data:hist.tx, color:css('--warn')}]);
    $('#live-dot').style.color = css('--ok');
  } catch (e) { $('#live-dot').style.color = css('--crit'); }
  finally { setTimeout(live, 3000); }
}
live();

// actions
function modal(title, out, ok) {
  $('#modal-title').textContent = title; $('#modal-title').className = ok === true ? 'ok' : ok === false ? 'crit' : '';
  $('#modal-out').textContent = out; $('#modal').classList.add('open');
}
$('#modal-close').onclick = () => $('#modal').classList.remove('open');
$('#modal').onclick = e => { if (e.target.id === 'modal') $('#modal').classList.remove('open'); };
document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#modal').classList.remove('open'); });

document.addEventListener('click', async e => {
  const lb = e.target.closest('[data-log]');
  if (lb) { $('#log-src').value = lb.dataset.log; loadLog(); $('#logs').scrollIntoView({behavior:'smooth'}); return; }
  const b = e.target.closest('[data-act]'); if (!b) return;
  const spec = JSON.parse(b.dataset.act);
  if (spec.confirm && !confirm(spec.confirm)) return;
  b.disabled = true; modal('Running: ' + b.textContent.trim() + '…', 'Please wait…');
  try {
    const r = await fetch('?api=action', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify(spec)});
    const j = await r.json();
    modal((j.ok ? '✓ ' : '✗ ') + j.title, j.out, j.ok);
  } catch (err) { modal('✗ Request failed', String(err) + '\n\n(If you restarted PHP-FPM, this is expected — refresh in a few seconds.)', false); }
  finally { b.disabled = false; }
});

// logs
let rawLog = '';
const errRe = /(error|crit|alert|emerg|fatal|exception|failed|denied|refused|timed out|killed)/i;
async function loadLog() {
  $('#log-out').textContent = 'Loading…'; $('#log-meta').textContent = '';
  try {
    const r = await fetch('?api=log&key=' + encodeURIComponent($('#log-src').value) + '&lines=' + $('#log-lines').value, {cache:'no-store'});
    const j = await r.json();
    rawLog = j.error ? j.error : (j.text || '(empty)');
    $('#log-meta').textContent = j.meta || '';
  } catch (e) { rawLog = 'Failed to load: ' + e; }
  renderLog();
}
function renderLog() {
  const f = $('#log-filter').value.toLowerCase(), eo = $('#log-err').checked, out = $('#log-out');
  const frag = document.createDocumentFragment();
  rawLog.split('\n').filter(l => (!f || l.toLowerCase().includes(f)) && (!eo || errRe.test(l))).forEach(l => {
    const d = document.createElement('div'); d.textContent = l;
    if (errRe.test(l)) d.className = 'err'; else if (/warn/i.test(l)) d.className = 'warn';
    frag.appendChild(d);
  });
  out.innerHTML = ''; out.appendChild(frag); out.scrollTop = out.scrollHeight;
}
$('#log-load').onclick = loadLog;
$('#log-filter').oninput = renderLog;
$('#log-err').onchange = renderLog;

// auto refresh (full page)
let autoOn = false;
try { autoOn = localStorage.getItem('srvmon-auto') === '1'; } catch (e) {}
$('#auto').checked = autoOn;
let autoT = autoOn ? setTimeout(() => { if (!$('#modal').classList.contains('open')) location.reload(); }, 60000) : null;
$('#auto').onchange = e => {
  try { localStorage.setItem('srvmon-auto', e.target.checked ? '1' : '0'); } catch (err) {}
  clearTimeout(autoT);
  if (e.target.checked) autoT = setTimeout(() => location.reload(), 60000);
};
</script>
</body>
</html>
