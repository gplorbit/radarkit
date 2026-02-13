<?php
/**
 * 🛡️ Database Bridge v2.0 - Instant Access to Adminer
 * Auto-login to Adminer using WordPress credentials from wp-config.php
 * SSO: Requires authentication via radar.php first
 */

session_start();

// --- WordPress Config Parser ---
function detectWPRoot()
{
    $current = __DIR__;
    for ($i = 0; $i < 5; $i++) {
        if (file_exists($current . DIRECTORY_SEPARATOR . 'wp-config.php'))
            return $current;
        $parent = dirname($current);
        if ($parent === $current)
            break;
        $current = $parent;
    }
    if (isset($_SERVER['SCRIPT_FILENAME'])) {
        $current = dirname($_SERVER['SCRIPT_FILENAME']);
        for ($i = 0; $i < 5; $i++) {
            if (file_exists($current . DIRECTORY_SEPARATOR . 'wp-config.php'))
                return $current;
            $parent = dirname($current);
            if ($parent === $current)
                break;
            $current = $parent;
        }
    }
    return null;
}

function parseWPConfig($siteRoot)
{
    $config = ['server' => 'localhost', 'username' => '', 'password' => '', 'db' => ''];
    if (!$siteRoot)
        return $config;
    $path = $siteRoot . DIRECTORY_SEPARATOR . 'wp-config.php';
    if (file_exists($path)) {
        $content = @file_get_contents($path);
        if (preg_match("/define\(\s*['\"]DB_NAME['\"],\s*['\"](.+?)['\"]\s*\);/", $content, $m))
            $config['db'] = $m[1];
        if (preg_match("/define\(\s*['\"]DB_USER['\"],\s*['\"](.+?)['\"]\s*\);/", $content, $m))
            $config['username'] = $m[1];
        if (preg_match("/define\(\s*['\"]DB_PASSWORD['\"],\s*['\"](.*?)['\"]\s*\);/", $content, $m))
            $config['password'] = $m[1];
        if (preg_match("/define\(\s*['\"]DB_HOST['\"],\s*['\"](.+?)['\"]\s*\);/", $content, $m))
            $config['server'] = $m[1];
    }
    return $config;
}

// --- SSO Check: Only allow if Radar session is active ---
if (!isset($_SESSION['radarkit_auth']['authorized']) || $_SESSION['radarkit_auth']['authorized'] !== true) {
    die('<div style="font-family:sans-serif;padding:50px;text-align:center;"><h2>⚠️ Akses Ditolak</h2><p>Silakan login melalui <a href="radar.php">RadarKit</a> terlebih dahulu.</p></div>');
}

// Check IP match for extra security
if ($_SESSION['radarkit_auth']['ip'] !== $_SERVER['REMOTE_ADDR']) {
    die('<div style="font-family:sans-serif;padding:50px;text-align:center;"><h2>⚠️ IP Mismatch</h2><p>Session tidak valid. Silakan <a href="radar.php">login ulang</a>.</p></div>');
}

$siteRoot = detectWPRoot();
$db = parseWPConfig($siteRoot);
?>
<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Database Bridge - Auto Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', sans-serif;
            background: #0c0c0e;
            color: #fff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 40px;
            max-width: 500px;
            width: 90%;
            text-align: center;
        }

        h1 {
            font-size: 1.5rem;
            margin-bottom: 10px;
            color: #ff8c00;
        }

        p {
            color: #a1a1aa;
            font-size: 0.9rem;
            margin-bottom: 20px;
        }

        .loader {
            width: 48px;
            height: 48px;
            border: 4px solid rgba(255, 140, 0, 0.2);
            border-top-color: #ff8c00;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }

        @keyframes spin {
            to {
                transform: rotate(360deg);
            }
        }

        .info-box {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            padding: 15px;
            text-align: left;
            margin-top: 20px;
        }

        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        .info-row:last-child {
            border-bottom: none;
        }

        .label {
            color: #71717a;
            font-size: 0.8rem;
        }

        .value {
            font-family: monospace;
            color: #fbbf24;
            font-size: 0.85rem;
        }

        .manual-link {
            display: inline-block;
            margin-top: 20px;
            color: #71717a;
            font-size: 0.8rem;
            text-decoration: underline;
        }
    </style>
</head>

<body>
    <div class="card">
        <h1>🔐 Auto-Login ke Database</h1>
        <p>Menghubungkan ke Adminer dengan kredensial WordPress...</p>
        <div class="loader"></div>
        <p style="color:#4ade80;">⏳ Mengautentikasi...</p>

        <div class="info-box">
            <div class="info-row"><span class="label">Server</span><span
                    class="value"><?php echo htmlspecialchars($db['server']); ?></span></div>
            <div class="info-row"><span class="label">Username</span><span
                    class="value"><?php echo htmlspecialchars($db['username']); ?></span></div>
            <div class="info-row"><span class="label">Database</span><span
                    class="value"><?php echo htmlspecialchars($db['db']); ?></span></div>
        </div>

        <a href="adminer-core.php?server=<?php echo urlencode($db['server']); ?>&username=<?php echo urlencode($db['username']); ?>&db=<?php echo urlencode($db['db']); ?>"
            class="manual-link">Klik di sini jika tidak redirect otomatis</a>
    </div>

    <!-- Hidden form untuk auto-submit ke Adminer -->
    <form id="adminerForm" method="post" action="adminer-core.php" style="display:none;">
        <input type="hidden" name="auth[driver]" value="server">
        <input type="hidden" name="auth[server]" value="<?php echo htmlspecialchars($db['server']); ?>">
        <input type="hidden" name="auth[username]" value="<?php echo htmlspecialchars($db['username']); ?>">
        <input type="hidden" name="auth[password]" value="<?php echo htmlspecialchars($db['password']); ?>">
        <input type="hidden" name="auth[db]" value="<?php echo htmlspecialchars($db['db']); ?>">
        <input type="hidden" name="auth[permanent]" value="1">
    </form>

    <script>
        // Auto-submit form setelah halaman dimuat
        document.addEventListener('DOMContentLoaded', function () {
            setTimeout(function () {
                document.getElementById('adminerForm').submit();
            }, 800); // Delay sedikit untuk UX yang lebih baik
        });
    </script>
</body>

</html>