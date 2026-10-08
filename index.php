<?php

function serviceStatus($service)
{
    $status = trim(shell_exec("systemctl is-active " . escapeshellarg($service) . " 2>/dev/null"));
    return $status === 'active';
}

function queueStatus($name)
{

    $output = shell_exec("sudo /usr/bin/supervisorctl status 2>/dev/null");
    foreach (explode("\n", $output) as $line) {
        if (str_starts_with(trim($line), $name . ':')) {
            return str_contains($line, 'RUNNING');
        }
    }

    return false;
}

$services = [
    'Nginx' => 'nginx',
    'PHP-FPM' => 'php8.4-fpm',
    'MySQL' => 'mysql',
    'Redis' => 'redis-server',
    'Supervisor' => 'supervisor',
];

$memory = shell_exec("free -m | awk '/Mem:/ {printf \"%d %d\", $3, $2}'");
[$usedMem, $totalMem] = array_map('intval', preg_split('/\s+/', trim($memory)));
$memPercent = $totalMem ? round(($usedMem / $totalMem) * 100) : 0;

$disk = shell_exec("df -P / | awk 'NR==2 {print $5}'");
$diskPercent = (int) rtrim(trim($disk), '%');

$cpu = shell_exec("top -bn1 | awk -F'[, ]+' '/Cpu/ {print 100-$8}'");
$cpuPercent = round((float) $cpu);

function badge($ok)
{
    return $ok
        ? '<span class="up">● UP</span>'
        : '<span class="down">● DOWN</span>';
}
?>
<!doctype html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="10">
    <title>InfluencerPro Server Status</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f4f6f8;
            margin: 0;
            padding: 30px;
            color: #222
        }

        .container {
            max-width: 900px;
            margin: auto
        }

        h1 {
            margin-bottom: 25px
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 15px
        }

        .card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 8px #0001
        }

        .name {
            font-size: 18px;
            font-weight: bold
        }

        .up {
            color: #16803c;
            font-weight: bold
        }

        .down {
            color: #c62828;
            font-weight: bold
        }

        .metric {
            font-size: 28px;
            font-weight: bold;
            margin-top: 10px
        }

        .small {
            color: #777;
            font-size: 13px
        }
    </style>
</head>

<body>
    <div class="container">

        <h1>InfluencerPro Server</h1>

        <div class="grid">

            <?php foreach ($services as $name => $service): ?>
                <div class="card">
                    <div class="name"><?= htmlspecialchars($name) ?></div>
                    <br>
                    <?= badge(serviceStatus($service)) ?>
                </div>
            <?php endforeach; ?>

            <div class="card">
                <div class="name">Realtime Queue</div>
                <br>
                <?= badge(queueStatus('influencerpro-realtime')) ?>
            </div>

            <div class="card">
                <div class="name">Default Queue</div>
                <br>
                <?= badge(queueStatus('influencerpro-default')) ?>
            </div>

            <div class="card">
                <div class="name">CPU</div>
                <div class="metric"><?= $cpuPercent ?>%</div>
            </div>

            <div class="card">
                <div class="name">RAM</div>
                <div class="metric"><?= $memPercent ?>%</div>
                <div class="small"><?= $usedMem ?> MB / <?= $totalMem ?> MB</div>
            </div>

            <div class="card">
                <div class="name">Disk</div>
                <div class="metric"><?= $diskPercent ?>%</div>
            </div>

        </div>

        <p class="small">Automatically refreshes every 10 seconds.</p>

    </div>
</body>

</html>