<?php
/**
 * 🛡️ RadarKit v4.5 Enterprise Edition
 * Professional Malware Detection & Advanced Heuristics
 * 
 * Features:
 * - Smart Engine: Entropy & Contextual Weighting.
 * - Core Integrity: Baseline MD5 comparison.
 * - Operasi Jantung: Safe Auto-Core-Replace.
 * - Enterprise Structure: Modular OOP.
 * -  External Signature Database
 * -  Database Scanner (wp_posts, wp_options, wp_users)
 */

session_start();
@ini_set('memory_limit', '512M');
@set_time_limit(300);
// HARDENING: Start output buffering immediately to catch any premature output
ob_start();

//  Load configuration (password, cloud signature URL)
require_once __DIR__ . '/radar_config.php';

//  Load external signature database and database scanner
require_once __DIR__ . '/radar_signatures.php';
require_once __DIR__ . '/radar_db.php';

class RadarUtils
{
    public static function rmdir($dir)
    {
        if (!is_dir($dir))
            return @unlink($dir);
        $items = scandir($dir);
        foreach ($items as $item) {
            if ($item == '.' || $item == '..')
                continue;
            self::rmdir($dir . DIRECTORY_SEPARATOR . $item);
        }
        return @rmdir($dir);
    }

    public static function xcopy($src, $dst)
    {
        if (is_dir($src)) {
            if (!is_dir($dst))
                @mkdir($dst, 0755, true);
            $files = scandir($src);
            foreach ($files as $file) {
                if ($file != "." && $file != "..")
                    self::xcopy("$src/$file", "$dst/$file");
            }
        } elseif (file_exists($src)) {
            @copy($src, $dst);
        }
    }

    public static function zipFolders($folders, $destination, $siteRoot)
    {
        if (!class_exists('ZipArchive'))
            return false;
        $zip = new ZipArchive();
        if ($zip->open($destination, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE)
            return false;

        foreach ($folders as $folder) {
            $fullPath = $siteRoot . DIRECTORY_SEPARATOR . $folder;
            if (!is_dir($fullPath))
                continue;

            $it = new RecursiveDirectoryIterator($fullPath);
            $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::LEAVES_ONLY);

            foreach ($files as $file) {
                if (!$file->isDir()) {
                    $filePath = $file->getRealPath();
                    $relativePath = $folder . '/' . substr($filePath, strlen($fullPath) + 1);
                    $zip->addFile($filePath, $relativePath);
                }
            }
        }
        return $zip->close();
    }

    public static function isExecEnabled()
    {
        $disabled = explode(',', ini_get('disable_functions'));
        return !in_array('exec', array_map('trim', $disabled)) && function_exists('exec');
    }
}

class RadarAuth
{
    // Tactical Key: Ganti passphrase ini sebelum deploy ke server klien
    private $passphrase = RADAR_PASSPHRASE;
    private $sessionKey = "radarkit_auth";

    public function handle()
    {
        if (isset($_GET['logout'])) {
            unset($_SESSION[$this->sessionKey]);
            session_destroy();
            header("Location: " . basename(__FILE__));
            exit;
        }

        $error = null;
        if (!isset($_SESSION[$this->sessionKey]) && isset($_POST['password'])) {
            if ($_POST['password'] === $this->passphrase) {
                // Ensure session is started and valid
                if (session_status() === PHP_SESSION_NONE)
                    session_start();
                session_regenerate_id(true);

                $_SESSION[$this->sessionKey] = [
                    'authorized' => true,
                    'token' => bin2hex(random_bytes(16)),
                    'ip' => $_SERVER['REMOTE_ADDR'],
                    'time' => time()
                ];
            } else {
                $error = "Password Salah!";
            }
        }

        if (!isset($_SESSION[$this->sessionKey])) {
            $this->displayLogin($error);
            exit;
        }

        // IP Lockdown: Prevent session hijacking across different IPs
        if ($_SESSION[$this->sessionKey]['ip'] !== $_SERVER['REMOTE_ADDR']) {
            session_destroy();
            $this->displayLogin("IP Mismatch! Session Reset.");
            exit;
        }

        return null;
    }

    private function displayLogin($error)
    {
        ?>
        <!DOCTYPE html>
        <html lang="id">

        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <title>RadarKit | Secure Access</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
            <style>
                :root {
                    --bg-grad: linear-gradient(90deg, #1c2429, #263238);
                    --accent: #ff8c00;
                }

                body {
                    background: var(--bg-grad);
                    color: #fff;
                    font-family: 'Inter', sans-serif;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                    -webkit-font-smoothing: antialiased;
                }

                .box {
                    background: rgba(38, 50, 56, 0.95);
                    padding: 40px;
                    border-radius: 16px;
                    border: 1px solid rgba(255, 255, 255, 0.08);
                    width: 340px;
                    text-align: center;
                    box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4);
                }

                h2 {
                    color: var(--accent);
                    margin-bottom: 25px;
                    font-weight: 600;
                    letter-spacing: 0.5px;
                }

                .input-group {
                    margin-bottom: 20px;
                }

                input {
                    width: 100%;
                    padding: 12px 15px;
                    border-radius: 10px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    background: rgba(0, 0, 0, 0.3);
                    color: #fff;
                    box-sizing: border-box;
                    font-family: inherit;
                    font-size: 14px;
                    transition: border-color 0.3s, box-shadow 0.3s;
                }

                input:focus {
                    outline: none;
                    border-color: var(--accent);
                    box-shadow: 0 0 0 3px rgba(255, 140, 0, 0.2);
                }

                button {
                    width: 100%;
                    padding: 12px;
                    border-radius: 10px;
                    border: none;
                    background: var(--accent);
                    color: #000;
                    font-weight: 600;
                    cursor: pointer;
                    font-size: 15px;
                    transition: transform 0.2s, background 0.2s;
                }

                button:hover {
                    background: #ffa733;
                    transform: translateY(-1px);
                }

                button:active {
                    transform: translateY(0);
                }

                .error {
                    color: #ff5252;
                    font-size: 13px;
                    margin-bottom: 15px;
                    background: rgba(255, 82, 82, 0.1);
                    padding: 8px;
                    border-radius: 6px;
                }
            </style>
        </head>

        <body>
            <div class="box">
                <h2>RadarKit Login</h2>
                <?php if ($error): ?>
                    <div class="error"><?php echo htmlspecialchars($error) ?></div>
                <?php endif; ?>
                <form method="post">
                    <div class="input-group">
                        <input type="password" name="password" placeholder="Passphrase" required autofocus>
                    </div>
                    <button type="submit">Unlock RadarKit</button>
                </form>
            </div>
        </body>

        </html>
        <?php
    }
}

class RadarDetector
{
    public $siteRoot;
    public $wpConfig = [];
    public $wpVersion = 'Unknown';
    public $dbConn = null;

    public function __construct()
    {
        // Strategy 1: Physical path (respects symlinks destination)
        $current = __DIR__;
        $this->siteRoot = $current;
        $found = false;

        for ($i = 0; $i < 5; $i++) {
            if (file_exists($current . DIRECTORY_SEPARATOR . 'wp-config.php')) {
                $this->siteRoot = $current;
                $found = true;
                break;
            }
            $parent = dirname($current);
            if ($parent === $current)
                break;
            $current = $parent;
        }

        // Strategy 2: Web-relative path (respects web server mapping/symlinks)
        if (!$found && isset($_SERVER['SCRIPT_FILENAME'])) {
            $current = dirname($_SERVER['SCRIPT_FILENAME']);
            for ($i = 0; $i < 5; $i++) {
                if (file_exists($current . DIRECTORY_SEPARATOR . 'wp-config.php')) {
                    $this->siteRoot = $current;
                    $found = true;
                    break;
                }
                $parent = dirname($current);
                if ($parent === $current)
                    break;
                $current = $parent;
            }
        }

        $this->detectVersion();
        $this->parseConfig();
        $this->connectDB();
        $this->detectMultisiteSites();
    }

    private function detectVersion()
    {
        $path = $this->siteRoot . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'version.php';
        if (file_exists($path)) {
            $content = @file_get_contents($path);
            if (preg_match('/\$wp_version\s*=\s*[\'"](.+?)[\'"]\s*;/', $content, $m)) {
                $this->wpVersion = $m[1];
            }
        }
    }

    private function parseConfig()
    {
        $path = $this->siteRoot . DIRECTORY_SEPARATOR . 'wp-config.php';
        if (file_exists($path)) {
            $content = @file_get_contents($path);
            preg_match("/define\(\s*['\"]DB_NAME['\"],\s*['\"](.+)['\"]\s*\);/", $content, $m_name);
            preg_match("/define\(\s*['\"]DB_USER['\"],\s*['\"](.+)['\"]\s*\);/", $content, $m_user);
            preg_match("/define\(\s*['\"]DB_PASSWORD['\"],\s*['\"](.+)['\"]\s*\);/", $content, $m_pass);
            preg_match("/define\(\s*['\"]DB_HOST['\"],\s*['\"](.+)['\"]\s*\);/", $content, $m_host);
            preg_match('/\$table_prefix\s*=\s*[\'"](.+?)[\'"]\s*;/', $content, $m_prefix);
            $this->wpConfig = [
                'name' => $m_name[1] ?? '',
                'user' => $m_user[1] ?? '',
                'pass' => $m_pass[1] ?? '',
                'host' => $m_host[1] ?? 'localhost',
                'prefix' => $m_prefix[1] ?? 'wp_',
                'is_multisite' => false,
                'sites' => []
            ];

            // Deteksi WordPress Multisite
            if (
                preg_match("/define\(\s*['\"]MULTISITE['\"]\s*,\s*true\s*\)/i", $content) ||
                preg_match("/define\(\s*['\"]WP_ALLOW_MULTISITE['\"]\s*,\s*true\s*\)/i", $content)
            ) {
                $this->wpConfig['is_multisite'] = true;
            }
        }
    }

    private function connectDB()
    {
        if (!empty($this->wpConfig['name'])) {
            try {
                $this->dbConn = new PDO(
                    "mysql:host={$this->wpConfig['host']};dbname={$this->wpConfig['name']};charset=utf8mb4",
                    $this->wpConfig['user'],
                    $this->wpConfig['pass'],
                    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
                );
            } catch (Exception $e) {
                $this->wpConfig['db_error'] = $e->getMessage();
            }
        }
    }

    /**
     * Deteksi sub-sites pada WordPress Multisite
     * Query tabel wp_blogs untuk mendapatkan daftar site beserta prefix-nya
     */
    private function detectMultisiteSites()
    {
        if (!$this->wpConfig['is_multisite'] || !$this->dbConn)
            return;

        try {
            $prefix = $this->wpConfig['prefix'];
            $blogsTable = $prefix . 'blogs';

            // Cek apakah tabel wp_blogs ada
            $check = $this->dbConn->query(
                "SELECT COUNT(*) FROM information_schema.tables 
                 WHERE table_schema = DATABASE() 
                 AND table_name = '{$blogsTable}'"
            );
            if ($check->fetchColumn() == 0) {
                $this->wpConfig['is_multisite'] = false;
                return;
            }

            $stmt = $this->dbConn->query(
                "SELECT blog_id, domain, path FROM {$blogsTable} 
                 WHERE deleted = 0 AND archived = 0 
                 ORDER BY blog_id ASC"
            );
            $blogs = $stmt->fetchAll();

            foreach ($blogs as $blog) {
                // Site utama (blog_id=1) pakai prefix standar, sub-site pakai prefix + blog_id
                $blogPrefix = ($blog['blog_id'] == 1)
                    ? $prefix
                    : $prefix . $blog['blog_id'] . '_';

                $this->wpConfig['sites'][] = [
                    'blog_id' => $blog['blog_id'],
                    'domain' => $blog['domain'],
                    'path' => $blog['path'],
                    'prefix' => $blogPrefix
                ];
            }
        } catch (Exception $e) {
            // Fallback: tetap jalan sebagai single site
            $this->wpConfig['is_multisite'] = false;
        }
    }
}

class RadarScanner
{
    private $siteRoot;
    private $freshCorePath;
    private $signatures;

    public function __construct($siteRoot, $signatures = null)
    {
        $this->siteRoot = $siteRoot;
        $this->freshCorePath = __DIR__ . DIRECTORY_SEPARATOR . 'fresh_core';
        $this->signatures = $signatures ?? SignatureProvider::getSignatures();
    }

    public function scan($dir)
    {
        $results = [];
        $badExt = ['php', 'phtml', 'php3', 'js', 'html', 'htaccess'];
        if (!is_dir($dir))
            return [];

        try {
            $it = new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS);
            $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::LEAVES_ONLY);
        } catch (Exception $e) {
            return []; // Fail gracefully if dir unreadable
        }

        foreach ($files as $file) {
            try {
                $path = $file->getRealPath();
                if (!$path)
                    continue;

                $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));

                // EXCLUSION LOGIC: Skip our own toolset directory (portable mode)
                // We use realpath to avoid issues with symlinks
                $toolDir = realpath(__DIR__);
                // Only skip if the toolDir is a SUBDIRECTORY of the current scan, 
                // OR if it's explicitly the tool directory itself.
                if (strpos($path, $toolDir) === 0 && $dir !== $toolDir) {
                    continue;
                }

                if ($path === __FILE__)
                    continue;
                if (!in_array($ext, $badExt))
                    continue;

                if ($this->verifyCoreIntegrity($path))
                    continue;

                // PERFORMANCE: Skip large files (>2MB) - not typical malware targets
                $fileSize = $file->getSize();
                if ($fileSize > 2097152) { // 2MB in bytes
                    continue;
                }

                $content = @file_get_contents($path);
                if ($content === false)
                    continue;

                $score = 0;
                $reasons = [];
                $fileHighlights = []; // Phase 9: Capture malicious blocks
                $weight = ($ext === 'js' ? 0.2 : 1.0);

                // Path Bias
                if (strpos($path, 'wp-content' . DIRECTORY_SEPARATOR . 'uploads') !== false) {
                    $score += 15;
                    $reasons[] = "Untrusted (Uploads)";
                }
                if (strpos($path, 'wp-admin') !== false || strpos($path, 'wp-includes') !== false) {
                    $score -= 5;
                }

                // Pattern Normalization
                $normalized = preg_replace('/[\s\.\'"]+/', '', $content);
                $isMinified = (strpos($path, '.min.') !== false || (strlen($normalized) / (substr_count($content, "\n") + 1) > 200));
                $isVendor = (preg_match('/\/vendor\/|\/node_modules\//i', $path));

                // 1. Smart Pattern Analysis (Kombinasi Pattern)
                // Deteksi berdasarkan kombinasi, bukan pattern tunggal
                $hasEval = (strpos($normalized, 'eval(') !== false);
                $hasBase64 = (strpos($normalized, 'base64_decode(') !== false);
                $hasGz = (strpos($normalized, 'gzinflate(') !== false ||
                    strpos($normalized, 'gzuncompress(') !== false);
                $hasPost = (strpos($normalized, '$_POST') !== false ||
                    strpos($normalized, '$_GET') !== false ||
                    strpos($normalized, '$_REQUEST') !== false);
                $inUploads = (strpos($path, 'uploads') !== false);

                if ($ext === 'php') {
                    // Triple combo: eval + base64 + gzip = MALWARE
                    if ($hasEval && $hasBase64 && $hasGz) {
                        $score += 30;
                        $reasons[] = "Obfuscated Backdoor (eval+base64+gz)";
                        $fileHighlights[] = "eval";
                        $fileHighlights[] = "base64_decode";
                        $fileHighlights[] = "gzinflate";
                    }
                    // eval + base64 + superglobal = MALWARE
                    elseif ($hasEval && $hasBase64 && $hasPost) {
                        $score += 25;
                        $reasons[] = "Dynamic Code Exec (eval+base64+POST)";
                        $fileHighlights[] = "eval";
                        $fileHighlights[] = "base64_decode";
                    }
                    // eval di uploads = SANGAT MENCURIGAKAN
                    elseif ($hasEval && $inUploads) {
                        $score += 20;
                        $reasons[] = "eval() in Uploads";
                        $fileHighlights[] = "eval";
                    }
                    // eval + base64 tanpa gzip = SUSPICIOUS
                    elseif ($hasEval && $hasBase64 && !$isVendor) {
                        $score += 15;
                        $reasons[] = "eval+base64 (Review)";
                        $fileHighlights[] = "eval";
                        $fileHighlights[] = "base64_decode";
                    }
                    // shell_exec tetap critical
                    if (strpos($normalized, 'shell_exec(') !== false) {
                        $score += 15;
                        $reasons[] = "shell_exec()";
                        $fileHighlights[] = "shell_exec";
                    }
                } elseif ($ext === 'js' && !$isMinified) {
                    // JS non-minified dengan eval = low score
                    if ($hasEval) {
                        $score += 3;
                        $reasons[] = "eval() in JS";
                        $fileHighlights[] = "eval";
                    }
                }

                // 2. Entropy Analysis (Calibrated)
                if (strlen($content) > 500 && substr($path, -13) !== 'wp-config.php') {
                    $entropy = $this->calculateEntropy($content);
                    $threshold = ($ext === 'js' ? 6.2 : 5.7);
                    if ($isMinified)
                        $threshold += 0.5;

                    if ($entropy > $threshold) {
                        $score += 12;
                        $reasons[] = "High Entropy ($entropy)";
                    }
                }

                // 3. Slang/Keywords - Judi Online (Cloud Signatures)
                foreach ($this->signatures['gamblingKeywords'] as $s) {
                    if (stripos($content, $s) !== false) {
                        $p = ($isVendor || $isMinified) ? 5 : 15;
                        $score += $p;
                        $reasons[] = "Gambling: $s";
                        $fileHighlights[] = $s;
                        break; // Only flag once per file
                    }
                }

                // 4. Specific .htaccess Injections & Redirection
                if ($ext === 'htaccess') {
                    if (preg_match('/RewriteCond.*HTTP_USER_AGENT.*(google|bing|yahoo|msn)/i', $content, $m)) {
                        $score += 25;
                        $reasons[] = "SEO Cloaking (Search Engine Specific)";
                        $fileHighlights[] = $m[0];
                    }
                    if (preg_match('/RewriteRule.*\.(php|html|js).*(http:\/\/|https:\/\/)/i', $content, $m)) {
                        $score += 20;
                        $reasons[] = "Suspicious Redirect (Third Party URL)";
                        $fileHighlights[] = $m[0];
                    }
                    if (strpos($content, 'SetEnvIf') !== false && strpos($content, 'referer') !== false) {
                        $score += 15;
                        $reasons[] = "Referer-based poisoning attempt";
                        $fileHighlights[] = "SetEnvIf";
                        $fileHighlights[] = "referer";
                    }
                }

                // 5. Emerging 2026 Patterns (Cryptojackers & Obfuscated Backdoors)
                if ($ext === 'php') {
                    if (strpos($normalized, '$_POST') !== false && (strpos($normalized, 'gzuncompress') !== false || strpos($normalized, 'gzinflate') !== false)) {
                        $score += 20;
                        $reasons[] = "Compressed POST Payload (Likely Backdoor)";
                        $fileHighlights[] = '$_POST';
                        $fileHighlights[] = 'gzinflate';
                    }
                    if (strpos($normalized, 'str_rot13(') !== false && strlen($normalized) < 1000) {
                        $score += 15;
                        $reasons[] = "Weak Obfuscation (str_rot13)";
                        $fileHighlights[] = 'str_rot13';
                    }
                }

                // 6. Advanced Backdoor Signatures
                if ($ext === 'php') {
                    // preg_replace with /e modifier (code execution)
                    if (preg_match('/preg_replace\s*\(\s*["\'].*\/e["\']/', $content, $m)) {
                        $score += 20;
                        $reasons[] = "preg_replace /e (Code Exec)";
                        $fileHighlights[] = $m[0];
                    }
                    // assert() - dynamic code execution
                    if (strpos($normalized, 'assert(') !== false) {
                        $score += 15;
                        $reasons[] = "assert() (Dynamic Exec)";
                        $fileHighlights[] = "assert";
                    }
                    // create_function() - deprecated anonymous function
                    if (strpos($normalized, 'create_function(') !== false) {
                        $score += 12;
                        $reasons[] = "create_function() (Deprecated)";
                        $fileHighlights[] = "create_function";
                    }
                    // Pola 4: VCD Malware ( Signatures)
                    if (strpos($normalized, '$GLOBALS[\'wp_vcd\']') !== false || strpos($normalized, '$GLOBALS["wp_vcd"]') !== false || strpos($content, '$wp_vcd =') !== false) {
                        $score += 40;
                        $reasons[] = "WP-VCD Malware";
                        $fileHighlights[] = "wp_vcd";
                    }
                    // Include injection via superglobals
                    if (preg_match('/@?include\s*\(\s*\$_(COOKIE|GET|POST|REQUEST)/i', $content, $m)) {
                        $score += 25;
                        $reasons[] = "Include Injection (Superglobal)";
                        $fileHighlights[] = $m[0];
                    }
                    // hex2bin obfuscation (hanya flag jika + eval combo)
                    if (strpos($normalized, 'hex2bin(') !== false) {
                        // hex2bin + eval = Obfuscation
                        if (strpos($normalized, 'eval(') !== false) {
                            $score += 15;
                            $reasons[] = "hex2bin + eval (Obfuscation)";
                            $fileHighlights[] = "hex2bin";
                            $fileHighlights[] = "eval";
                        }
                    }

                    // 6b. Extended Backdoor Signatures (Cloud Signatures)
                    foreach ($this->signatures['backdoorPatterns'] as $pattern => $config) {
                        if (preg_match($pattern, $content, $m)) {
                            $score += $config['score'];
                            $reasons[] = $config['label'];
                            $fileHighlights[] = $m[0];
                            break; // Only flag first match per file
                        }
                    }
                }

                // 7. Japanese Keyword Hack Detection (Smart Detection)
                // SKIP untuk JS (i18n library), STRICT untuk PHP
                if ($ext !== 'js') {
                    $hasJapaneseSpamKeyword = false;
                    foreach ($this->signatures['japaneseSpamKeywords'] as $jp) {
                        if (strpos($content, $jp) !== false) {
                            $hasJapaneseSpamKeyword = true;
                            $fileHighlights[] = $jp;
                            break;
                        }
                    }

                    if ($hasJapaneseSpamKeyword && $ext === 'php') {
                        $hasHiddenCSS = preg_match('/display\s*:\s*none|visibility\s*:\s*hidden/i', $content);
                        $hasExternalLink = preg_match('/<a\s+[^>]*href\s*=\s*["\']https?:\/\/[^"\']+/i', $content);

                        if ($hasHiddenCSS && $hasExternalLink) {
                            // Hidden + external link = SEO SPAM
                            $score += 30;
                            $reasons[] = "Japanese SEO Spam (Hidden+Link)";
                            $fileHighlights[] = "display:none";
                            $fileHighlights[] = "visibility:hidden";
                        } elseif ($hasHiddenCSS) {
                            $score += 20;
                            $reasons[] = "Japanese Keyword Hack (Hidden)";
                            $fileHighlights[] = "display:none";
                            $fileHighlights[] = "visibility:hidden";
                        }
                        // Jika tidak ada hidden CSS, skip (likely false positive)
                    }
                }

                // 8. Chinese Keyword Hack Detection (Smart Detection)
                // Konsisten dengan Japanese detection
                if ($ext !== 'js') {
                    $hasChineseSpamKeyword = false;
                    foreach ($this->signatures['chineseSpamKeywords'] as $cn) {
                        if (strpos($content, $cn) !== false) {
                            $hasChineseSpamKeyword = true;
                            $fileHighlights[] = $cn;
                            break;
                        }
                    }

                    if ($hasChineseSpamKeyword && $ext === 'php') {
                        $hasHiddenCSS = preg_match('/display\s*:\s*none|visibility\s*:\s*hidden/i', $content);
                        $hasExternalLink = preg_match('/<a\s+[^>]*href\s*=\s*["\']https?:\/\/[^"\']+/i', $content);

                        if ($hasHiddenCSS && $hasExternalLink) {
                            $score += 30;
                            $reasons[] = "Chinese SEO Spam (Hidden+Link)";
                            $fileHighlights[] = "display:none";
                            $fileHighlights[] = "visibility:hidden";
                        } elseif ($hasHiddenCSS) {
                            $score += 20;
                            $reasons[] = "Chinese Keyword Hack (Hidden)";
                            $fileHighlights[] = "display:none";
                            $fileHighlights[] = "visibility:hidden";
                        }
                    }
                }

                // 9. Pharma Hack Detection
                foreach ($this->signatures['pharmaKeywords'] as $pharma) {
                    if (stripos($content, $pharma) !== false && !$isVendor) {
                        $score += 15;
                        $reasons[] = "Pharma: $pharma";
                        $fileHighlights[] = $pharma;
                        break;
                    }
                }
                // Hidden pharma links
                if (preg_match('/style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\'].*?(viagra|cialis|pharmacy)/is', $content, $m)) {
                    $score += 25;
                    $reasons[] = "Hidden Pharma Link";
                    $fileHighlights[] = $m[0];
                }

                // Redirect to .jp domain
                if (preg_match('/(header\s*\(|location\s*[:=]).*\.jp[\/\'"]/i', $content, $m)) {
                    $score += 15;
                    $reasons[] = "Redirect to .jp Domain";
                    $fileHighlights[] = $m[0];
                }

                // ================================================================
                // ENHANCED DETECTION (4 Phases) - Fixed
                // ================================================================

                // PHASE 1: Deteksi File Asing di WordPress Core
                // File di wp-admin/wp-includes yang TIDAK ada di fresh_core = mencurigakan
                // ONLY run if fresh_core directory exists and has content
                $relPath = str_replace($this->siteRoot, '', $path);
                $freshCoreExists = is_dir($this->freshCorePath) &&
                    (is_dir($this->freshCorePath . '/wp-admin') || is_dir($this->freshCorePath . '/wp-includes'));

                if (
                    $freshCoreExists &&
                    (strpos($path, 'wp-admin' . DIRECTORY_SEPARATOR) !== false ||
                        strpos($path, 'wp-includes' . DIRECTORY_SEPARATOR) !== false)
                ) {

                    // Whitelist legitimate dropins
                    $legitimateInCore = [
                        '/wp-admin/install.php',
                        '/wp-admin/upgrade.php',
                    ];

                    $freshPath = $this->freshCorePath . $relPath;
                    if (!file_exists($freshPath) && !in_array($relPath, $legitimateInCore)) {
                        $score += 30;
                        $reasons[] = "Unknown file in WordPress core";
                    }
                }

                // PHASE 2: Enhanced Theme File Detection
                $themeFiles = ['functions.php', 'header.php', 'footer.php', 'index.php'];
                $basename = basename($path);

                if (in_array($basename, $themeFiles) && strpos($path, 'wp-content' . DIRECTORY_SEPARATOR . 'themes') !== false) {
                    // Cek injeksi sebelum tag PHP (malware sering inject di awal file)
                    if (preg_match('/^[^<]*<script|^[^<]*<\?php\s*eval/s', $content, $m)) {
                        $score += 25;
                        $reasons[] = "Injection at file start";
                        $fileHighlights[] = $m[0];
                    }

                    // Cek eval/base64 di functions.php (sangat mencurigakan)
                    if ($basename === 'functions.php' && preg_match('/eval\s*\(\s*base64_decode/', $content, $m)) {
                        $score += 30;
                        $reasons[] = "Obfuscated code in functions.php";
                        $fileHighlights[] = $m[0];
                    }

                    // Cek external script injection di header/footer (exclude known CDNs)
                    if (($basename === 'header.php' || $basename === 'footer.php')) {
                        $safeDomains = 'googleapis|gstatic|cloudflare|jquery|wp-includes|google-analytics|googletagmanager|facebook|twitter';
                        if (preg_match('/<script[^>]*src=["\'][^"\']*https?:\/\/(?!' . $safeDomains . ')[^"\']+["\']/', $content, $m)) {
                            $score += 15;
                            $reasons[] = "Unknown external script in theme";
                            $fileHighlights[] = $m[0];
                        }
                    }
                }

                // PHASE 3: Enhanced htaccess Detection (Cloaking Patterns)
                // SKIP if already flagged by previous htaccess detection (avoid double scoring)
                $hasPreviousHtaccessFlag = in_array("SEO Cloaking (Search Engine Specific)", $reasons);

                if ($ext === 'htaccess' && !$hasPreviousHtaccessFlag) {
                    // Bot-specific cloaking (more granular than previous check)
                    if (preg_match('/RewriteCond.*HTTP_USER_AGENT.*Googlebot/i', $content, $m)) {
                        $score += 25;
                        $reasons[] = "Googlebot cloaking";
                        $fileHighlights[] = $m[0];
                    }
                    if (preg_match('/RewriteCond.*HTTP_USER_AGENT.*Bingbot/i', $content, $m)) {
                        $score += 25;
                        $reasons[] = "Bingbot cloaking";
                        $fileHighlights[] = $m[0];
                    }
                    // Redirect chain detection
                    if (preg_match_all('/RewriteRule.*\[R=(301|302)\]/i', $content, $m) >= 2) {
                        $score += 20;
                        $reasons[] = "Redirect chain detected";
                        foreach ($m[0] as $match)
                            $fileHighlights[] = $match;
                    }
                    // Referrer-based redirect (from search engines)
                    if (preg_match('/RewriteCond.*HTTP_REFERER.*(google|bing|yahoo)/i', $content, $m)) {
                        $score += 25;
                        $reasons[] = "Referrer-based SEO redirect";
                        $fileHighlights[] = $m[0];
                    }
                }

                // PHASE 4: Doorway Pages Detection
                // File PHP dengan banyak keyword gambling di luar plugins/themes = doorway page
                // SKIP if already flagged single gambling keyword (avoid double scoring)
                $hasGamblingFlag = false;
                foreach ($reasons as $r) {
                    if (strpos($r, 'Gambling:') !== false) {
                        $hasGamblingFlag = true;
                        break;
                    }
                }

                if (
                    !$hasGamblingFlag && $ext === 'php' &&
                    strpos($path, 'wp-content' . DIRECTORY_SEPARATOR . 'plugins') === false &&
                    strpos($path, 'wp-content' . DIRECTORY_SEPARATOR . 'themes') === false
                ) {

                    $gamblingKeywordCount = 0;
                    $gamblingKeywords = $this->signatures['gamblingKeywords'];

                    foreach ($gamblingKeywords as $keyword) {
                        if (stripos($content, $keyword) !== false) {
                            $gamblingKeywordCount++;
                            $fileHighlights[] = $keyword;
                        }
                    }

                    // 5+ keyword gambling = CRITICAL doorway page
                    if ($gamblingKeywordCount >= 5) {
                        $score += 35;
                        $reasons[] = "Doorway page ({$gamblingKeywordCount} gambling keywords)";
                    } elseif ($gamblingKeywordCount >= 3) {
                        $score += 20;
                        $reasons[] = "Potential doorway page ({$gamblingKeywordCount} keywords)";
                    }
                }

                // PHASE 5: Cloaking Pattern Detection (v4.5 Improved)
                // Deteksi script PHP yang mengecek User-Agent untuk cloaking
                if ($ext === 'php') {
                    // Pattern: strpos/preg_match/strstr dengan nama bot
                    $botPattern = '/(strpos|preg_match|strstr|stripos)\s*\(.*(google|bing|yahoo|msn|bot|crawler|spider).*["\']/i';
                    if (preg_match($botPattern, $content, $m)) {
                        $score += 25;
                        $reasons[] = "Advanced cloaking pattern detected";
                        $fileHighlights[] = $m[0];
                    }
                    // Direct HTTP_USER_AGENT conditional
                    if (preg_match('/if\s*\(.*HTTP_USER_AGENT.*(google|bing|yahoo|bot|crawler|spider)/i', $content, $m)) {
                        $score += 25;
                        $reasons[] = "User-Agent based cloaking";
                        $fileHighlights[] = $m[0];
                    }
                    // Eval with recursive wrappers (Webshell signature v4.5)
                    // Matches eval(base64_decode($_GET...)), eval(gzinflate($_POST...)), etc.
                    $evalWrapper = '/eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|@?)\s*\(?\s*((base64_decode|gzinflate|@?)\s*\(?\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i';
                    if (preg_match($evalWrapper, $content, $m)) {
                        $score += 50;
                        $reasons[] = "Webshell: Obfuscated eval with user input";
                        $fileHighlights[] = $m[0];
                    }
                }

                // PHASE 6: Japanese/Chinese Keyword Hack Detection 
                // Deteksi file dengan banyak karakter non-Latin (Jepang/China)
                if (in_array($ext, ['html', 'php', 'htm'])) {
                    // Count Japanese/Chinese characters (Unicode ranges)
                    // Hiragana: 3040-309F, Katakana: 30A0-30FF, CJK: 4E00-9FFF
                    $nonLatinCount = preg_match_all('/[\x{3040}-\x{309F}\x{30A0}-\x{30FF}\x{4E00}-\x{9FFF}]/u', $content);

                    if ($nonLatinCount >= 50) {
                        // Check if file is in suspicious location (not in themes/plugins)
                        $inThemes = strpos($path, 'wp-content' . DIRECTORY_SEPARATOR . 'themes') !== false;
                        $inPlugins = strpos($path, 'wp-content' . DIRECTORY_SEPARATOR . 'plugins') !== false;

                        if (!$inThemes && !$inPlugins) {
                            $score += 30;
                            $reasons[] = "Japanese/Chinese keyword hack ({$nonLatinCount} chars)";
                        } elseif ($nonLatinCount >= 200) {
                            // Even in themes, too many non-Latin chars is suspicious
                            $score += 15;
                            $reasons[] = "Excessive non-Latin content ({$nonLatinCount} chars)";
                        }
                    }

                    // Specific Japanese spam keywords
                    $japaneseSpamKeywords = ['激安', '偽ブランド', '格安', 'コピー品', '送料無料'];
                    foreach ($japaneseSpamKeywords as $jpKeyword) {
                        if (strpos($content, $jpKeyword) !== false) {
                            $score += 20;
                            $reasons[] = "Japanese spam keyword detected";
                            $fileHighlights[] = $jpKeyword;
                            break;
                        }
                    }
                }

                // PHASE 7: Enhanced Evil External Script Detection 
                // Lebih agresif untuk mendeteksi script injection di semua file
                if (in_array($ext, ['php', 'html', 'htm'])) {
                    // Malicious CDN/domain patterns
                    $evilDomains = $this->signatures['evilDomains'];
                    foreach ($evilDomains as $domain) {
                        if (stripos($content, $domain) !== false) {
                            $score += 25;
                            $reasons[] = "Malicious domain reference: {$domain}";
                            $fileHighlights[] = $domain;
                            break;
                        }
                    }

                    // Generic external script from non-standard domains
                    // Exclude safe CDNs more strictly
                    $safeCDNs = 'googleapis|gstatic|cloudflare|jquery|wp\\.org|wordpress\\.com|google|facebook|twitter|cdn\\.|jsdelivr|unpkg';
                    if (preg_match('/<script[^>]*src=["\'][^"\']*https?:\/\/(?!' . $safeCDNs . ')([^"\'\/]+)/i', $content, $m)) {
                        $score += 15;
                        $reasons[] = "Unknown external script: {$m[1]}";
                        $fileHighlights[] = $m[0];
                    }
                }

                // PHASE 8: Popular Malware Variable Names (v4.5)
                if ($ext === 'php') {
                    $badVars = ['\$auth_pass', '\$default_use_cookie', '\$default_password', '\$sh_ver', '\$sds_pass'];
                    foreach ($badVars as $bv) {
                        if (preg_match('/' . $bv . '\s*=/', $content, $m)) {
                            $score += 20;
                            $reasons[] = "Popular malware variable name: " . stripslashes($bv);
                            $fileHighlights[] = $m[0];
                        }
                    }
                }

                // ================================================================
                // END ENHANCED DETECTION
                // ================================================================

                if ($score >= 10) {
                    $results[] = [
                        'path' => $path,
                        'rel_path' => str_replace($this->siteRoot, '', $path),
                        'reason' => implode(', ', array_unique($reasons)),
                        'severity' => ($score >= 20 ? 'CRITICAL' : 'SUSPICIOUS'),
                        'score' => round($score, 1),
                        'size' => round($file->getSize() / 1024, 2) . ' KB',
                        'highlights' => array_values(array_unique($fileHighlights)) // Phase 9
                    ];
                }
            } catch (Exception $e) {
                // Skip file if any single file error occurs
                continue;
            }
        }
        return $results;
    }

    private function verifyCoreIntegrity($path)
    {
        $rel = str_replace($this->siteRoot, '', $path);
        $fresh = $this->freshCorePath . $rel;
        return (file_exists($fresh) && filesize($path) === filesize($fresh) && md5_file($path) === md5_file($fresh));
    }

    private function calculateEntropy($str)
    {
        $size = strlen($str);
        if ($size === 0)
            return 0;
        $freq = array_count_values(str_split($str));
        $entropy = 0;
        foreach ($freq as $f) {
            $p = $f / $size;
            $entropy -= $p * log($p, 2);
        }
        return $entropy;
    }
}

class RadarActions
{
    private $detector;

    public function __construct($detector)
    {
        $this->detector = $detector;
    }

    public function handle($action)
    {
        // Decode target if sent as base64 (Robustness Fix)
        $target = '';
        if (isset($_POST['target_b64'])) {
            $target = base64_decode($_POST['target_b64']);
        } else {
            $target = $_POST['target'] ?? '';
        }

        try {
            // Fix path resolution issues
            $realRoot = realpath($this->detector->siteRoot);
            if (!$realRoot)
                $realRoot = $this->detector->siteRoot;
            $realRoot = rtrim($realRoot, DIRECTORY_SEPARATOR);

            // Allow empty target for core sync or non-file actions
            $dbActions = [
                'db_scan',
                'get_multisite_info',
                'db_scan_posts',
                'db_scan_options',
                'db_scan_users',
                'db_scan_redirects', // v4.7.6: Added missing scan action
                'db_delete_posts',
                'db_delete_options',
                'db_delete_users',   // v4.7.6: Added missing delete action
                'db_delete_redirects' // v4.7.6: Added missing delete action
            ];
            if (!in_array($action, array_merge(['sync_core', 'replace_core', 'export_results', 'bulk_delete', 'file_scan'], $dbActions))) {
                $realTarget = realpath($target);
                // Fallback attempt if file exists but realpath fails
                if (!$realTarget || !file_exists($realTarget)) {
                    if (!file_exists($target))
                        throw new Exception("File not found: $target");

                    // SECURITY HARDENING: Prevent Path Traversal if using raw target
                    // Reject any path containing '..' components to prevent escaping root
                    if (strpos($target, '..') !== false) {
                        throw new Exception("Security Violation: Path Traversal Detected.");
                    }

                    $realTarget = $target;
                }

                // Security Check: Prevent traversing outside root
                // Use normalize logical check if realpath unavailable
                if (strpos($realTarget, $realRoot) !== 0) {
                    throw new Exception("Access Denied: Target is outside Site Root.");
                }
            } else {
                $realTarget = '';
            }

            switch ($action) {
                case 'delete_file':
                    return $this->deleteFile($realTarget);

                case 'view_file':
                    $content = @file_get_contents($realTarget);
                    if ($content === false)
                        throw new Exception("Gagal membaca file (Permissions?).");

                    // FIXED: Send as Base64 to bypass ALL encoding issues (JSON safe)
                    return ['status' => 'success', 'data_b64' => base64_encode($content)];

                case 'sync_core':
                    return $this->syncCore($_POST['version'] ?? '');

                case 'replace_core':
                    return $this->replaceCore();

                // Quick Actions
                case 'bulk_delete':
                    $paths = json_decode($_POST['paths'] ?? '[]', true);
                    return $this->bulkDelete($paths, $realRoot);

                case 'export_results':
                    return $this->exportResults();

                // AJAX File Scan
                case 'file_scan':
                    return $this->fileScan();

                //  Database Scan Actions
                case 'db_scan':
                    return $this->dbFullScan();

                case 'get_multisite_info':
                    return [
                        'status' => 'success',
                        'is_multisite' => $this->detector->wpConfig['is_multisite'],
                        'sites' => $this->detector->wpConfig['sites'] ?? []
                    ];

                case 'db_scan_posts':
                    return $this->dbScanPosts();

                case 'db_scan_options':
                    return $this->dbScanOptions();

                case 'db_scan_users':
                    return $this->dbScanUsers();

                case 'db_delete_posts':
                    $ids = json_decode($_POST['ids'] ?? '[]', true);
                    return $this->dbDeletePosts($ids);

                case 'db_delete_options':
                    $ids = json_decode($_POST['ids'] ?? '[]', true);
                    return $this->dbDeleteOptions($ids);

                case 'db_delete_users':
                    $ids = json_decode($_POST['ids'] ?? '[]', true);
                    return $this->dbDeleteUsers($ids);

                case 'db_delete_redirects':
                    $ids = json_decode($_POST['ids'] ?? '[]', true);
                    return $this->dbDeleteRedirects($ids);
            }
        } catch (Exception $e) {
            return ['status' => 'error', 'msg' => $e->getMessage()];
        }
    }

    private function syncCore($v)
    {
        if (empty($v))
            throw new Exception("Invalid Version.");

        // Fix Timeout Issues: Unlimited execution time for download/extract
        @set_time_limit(0);
        @ini_set('max_execution_time', 0);

        if (!function_exists('curl_init'))
            throw new Exception("PHP 'cURL' tidak aktif.");
        if (!class_exists('ZipArchive'))
            throw new Exception("PHP 'ZipArchive' tidak aktif.");

        $dest = __DIR__ . DIRECTORY_SEPARATOR . 'fresh_core';
        if (!is_writable(__DIR__))
            throw new Exception("Folder " . basename(__DIR__) . " tidak dapat ditulis (CHMOD 755).");

        // Pre-flight connection test to diagnose network issues
        $testUrl = "https://wordpress.org/";
        $testCh = curl_init($testUrl);
        curl_setopt($testCh, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($testCh, CURLOPT_TIMEOUT, 10); // Short timeout for test
        curl_setopt($testCh, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($testCh, CURLOPT_NOBODY, true); // HEAD request only
        curl_setopt($testCh, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($testCh, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($testCh, CURLOPT_USERAGENT, 'RadarKit/4.5');

        // Force IPv4 to avoid IPv6 issues on some servers
        if (defined('CURLOPT_IPRESOLVE') && defined('CURL_IPRESOLVE_V4')) {
            curl_setopt($testCh, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        }

        curl_exec($testCh);
        $testHttpCode = curl_getinfo($testCh, CURLINFO_HTTP_CODE);
        $testErr = curl_error($testCh);
        curl_close($testCh);

        if ($testHttpCode == 0) {
            $hints = [
                "Pastikan server memiliki akses internet.",
                "Periksa firewall/SELinux: 'sudo setsebool -P httpd_can_network_connect 1'",
                "Cek DNS resolver: 'cat /etc/resolv.conf'",
                "Coba dari CLI: 'curl -I https://wordpress.org/'"
            ];
            throw new Exception("Tidak dapat terhubung ke wordpress.org. " . ($testErr ?: "Network blocked.") . "\n\nTroubleshooting:\n• " . implode("\n• ", $hints));
        }

        // Try specific version first, fallback to latest if fails
        $url = "https://wordpress.org/wordpress-{$v}.zip";
        // Fallback or Force Latest: https://wordpress.org/latest.zip

        $zip = __DIR__ . DIRECTORY_SEPARATOR . 'core.zip';
        if (file_exists($zip))
            @unlink($zip);

        $ch = curl_init($url);
        $fp = fopen($zip, 'wb');
        if (!$fp)
            throw new Exception("Gagal membuat core.zip (Check Permissions).");

        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'RadarKit/4.5');
        curl_setopt($ch, CURLOPT_TIMEOUT, 300); // 5 menit untuk download
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);

        // Force IPv4
        if (defined('CURLOPT_IPRESOLVE') && defined('CURL_IPRESOLVE_V4')) {
            curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        }

        // AUTO-SSL: Disable verification on localhost for better compatibility
        $isLocal = in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1']) || stripos($_SERVER['HTTP_HOST'], 'localhost') !== false;
        if ($isLocal) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        } else {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        }

        $curlResult = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        fclose($fp);

        // DEBUG: Validate download result
        $zipExists = file_exists($zip);
        $zipSize = $zipExists ? filesize($zip) : 0;

        if ($httpCode != 200 || !$zipExists || $zipSize < 1000) {
            if ($zipExists)
                @unlink($zip);
            $msg = "Gagal unduh Core v$v. [HTTP: $httpCode, Size: $zipSize bytes]";
            if ($err)
                $msg .= " Curl Error: $err";
            throw new Exception($msg);
        }

        $z = new ZipArchive;
        $openResult = $z->open($zip);
        if ($openResult === TRUE) {
            $temp = $dest . '_temp';
            if (!is_dir($dest))
                @mkdir($dest, 0755, true);
            $z->extractTo($temp);
            $z->close();
            @unlink($zip);

            $extDir = $temp . DIRECTORY_SEPARATOR . 'wordpress';
            if (is_dir($extDir)) {
                // STRICT FILTER: Remove all non-essential system files
                $removals = ['wp-content', 'wp-config-sample.php', 'readme.html', 'license.txt'];
                foreach ($removals as $item) {
                    RadarUtils::rmdir($extDir . DIRECTORY_SEPARATOR . $item);
                }

                if (RadarUtils::isExecEnabled()) {
                    exec("rm -rf " . escapeshellarg($dest) . " && mv " . escapeshellarg($extDir) . " " . escapeshellarg($dest) . " && rm -rf " . escapeshellarg($temp));
                } else {
                    RadarUtils::rmdir($dest);
                    RadarUtils::xcopy($extDir, $dest);
                    RadarUtils::rmdir($temp);
                }
                return ['status' => 'success', 'msg' => "Core v$v Ready."];
            } else {
                // DEBUG: Extraction dir not found
                throw new Exception("Gagal ekstraksi: folder 'wordpress' tidak ditemukan di dalam zip.");
            }
        } else {
            // DEBUG: ZipArchive open failed
            throw new Exception("Gagal membuka zip (Error code: $openResult).");
        }
    }

    private function replaceCore()
    {
        $dest = __DIR__ . DIRECTORY_SEPARATOR . 'fresh_core';
        // Operation Jantung & Safety Guard
        $root = $this->detector->siteRoot;

        $items = scandir($root);
        foreach ($items as $item) {
            if (isset($item[0]) && $item[0] == '.')
                continue; // Skip hidden/dot files if wanted, but standard loop handles . and ..

            // Safety Guards
            if (in_array($item, ['wp-config.php', '.htaccess', 'wp-content', 'radarkit']))
                continue;
            if (strpos($item, 'radar.php') === 0)
                continue;

            $path = $root . DIRECTORY_SEPARATOR . $item;
            RadarUtils::rmdir($path);
        }

        // Injection
        if (RadarUtils::isExecEnabled()) {
            exec("cp -rn " . escapeshellarg($dest) . "/. " . escapeshellarg($root) . "/");
        } else {
            RadarUtils::xcopy($dest, $root);
        }
        return ['status' => 'success', 'msg' => "Operasi Jantung Selesai!"];
    }

    private function deleteFile($path)
    {
        if (!is_file($path))
            throw new Exception("File target hilang.");

        // Try simple delete first
        if (@unlink($path)) {
            return ['status' => 'success', 'msg' => 'File BERHASIL dihapus.'];
        }

        // If failed, try to chmod and force delete
        @chmod($path, 0666);
        if (@unlink($path)) {
            return ['status' => 'success', 'msg' => 'File dihapus (setelah chmod).'];
        }

        @copy($path, $path . '.bak'); // Safety copy last resort? No, useless if we can't delete.

        // Retry force
        $base = basename($path);
        $dir = dirname($path);
        if (is_writable($dir)) {
            // Try to overwrite with empty then unlink?
            file_put_contents($path, "");
            if (@unlink($path))
                return ['status' => 'success', 'msg' => 'File dihapus paksa.'];
        }

        throw new Exception("Gagal menghapus file. Pastikan folder parent writable.");
    }

    // Bulk delete multiple files
    private function bulkDelete($paths, $realRoot)
    {
        if (!is_array($paths) || empty($paths)) {
            throw new Exception("Tidak ada file yang dipilih.");
        }

        $deleted = 0;
        $failed = 0;

        foreach ($paths as $path) {
            $realPath = realpath($path);
            if (!$realPath)
                $realPath = $path;

            // Security: ensure within root
            if (strpos($realPath, $realRoot) !== 0) {
                $failed++;
                continue;
            }

            if (is_file($realPath) && @unlink($realPath)) {
                $deleted++;
            } else {
                $failed++;
            }
        }

        return ['status' => 'success', 'msg' => "Dihapus: $deleted, Gagal: $failed"];
    }

    // Export scan results
    private function exportResults()
    {
        $scanner = new RadarScanner($this->detector->siteRoot);
        $results = $scanner->scan($this->detector->siteRoot);
        $export = [
            'scan_time' => date('Y-m-d H:i:s'),
            'root' => $this->detector->siteRoot,
            'summary' => [
                'total' => count($results),
                'critical' => count(array_filter($results, fn($r) => $r['severity'] === 'CRITICAL')),
                'suspicious' => count(array_filter($results, fn($r) => $r['severity'] === 'SUSPICIOUS')),
            ],
            'results' => $results
        ];
        return ['status' => 'success', 'data' => $export];
    }

    // AJAX File Scan
    private function fileScan()
    {
        $scanner = new RadarScanner($this->detector->siteRoot);
        $results = $scanner->scan($this->detector->siteRoot);
        return [
            'status' => 'success',
            'data' => [
                'results' => $results,
                'summary' => [
                    'total' => count($results),
                    'critical' => count(array_filter($results, fn($r) => $r['severity'] === 'CRITICAL')),
                    'suspicious' => count(array_filter($results, fn($r) => $r['severity'] === 'SUSPICIOUS')),
                ],
                'root' => $this->detector->siteRoot,
                'timestamp' => date('Y-m-d H:i:s')
            ]
        ];
    }

    //  Database Scan Methods
    private function getDBScanner($siteId = null)
    {
        if (!$this->detector->dbConn) {
            throw new Exception("Database tidak terhubung.");
        }

        $prefix = $this->detector->wpConfig['prefix'] ?? 'wp_';

        // Multisite: gunakan prefix sub-site jika diminta
        if ($siteId !== null && $this->detector->wpConfig['is_multisite']) {
            $found = false;
            foreach ($this->detector->wpConfig['sites'] as $site) {
                if ($site['blog_id'] == $siteId) {
                    $prefix = $site['prefix'];
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                throw new Exception("Site ID {$siteId} tidak ditemukan.");
            }
        }

        return new RadarDBScanner(
            $this->detector->dbConn,
            $prefix
        );
    }

    private function dbFullScan()
    {
        $siteId = isset($_POST['site_id']) ? intval($_POST['site_id']) : null;
        $scanner = $this->getDBScanner($siteId);
        $results = $scanner->runFullScan(500);
        return ['status' => 'success', 'data' => $results];
    }

    private function dbScanPosts()
    {
        $siteId = isset($_POST['site_id']) ? intval($_POST['site_id']) : null;
        $scanner = $this->getDBScanner($siteId);
        $limit = intval($_POST['limit'] ?? 500);
        $results = $scanner->scanPosts($limit);
        return ['status' => 'success', 'data' => $results];
    }

    private function dbScanOptions()
    {
        $siteId = isset($_POST['site_id']) ? intval($_POST['site_id']) : null;
        $scanner = $this->getDBScanner($siteId);
        $results = $scanner->scanOptions();
        return ['status' => 'success', 'data' => $results];
    }

    private function dbScanUsers()
    {
        $siteId = isset($_POST['site_id']) ? intval($_POST['site_id']) : null;
        $scanner = $this->getDBScanner($siteId);
        $results = $scanner->scanUsers();
        return ['status' => 'success', 'data' => $results];
    }

    private function dbDeletePosts($ids)
    {
        if (empty($ids) || !is_array($ids)) {
            throw new Exception("Tidak ada post yang dipilih.");
        }
        $siteId = isset($_POST['site_id']) ? intval($_POST['site_id']) : null;
        $scanner = $this->getDBScanner($siteId);
        $result = $scanner->deleteSpamPosts($ids);
        if ($result['status'] === 'error') {
            throw new Exception($result['msg']);
        }
        return ['status' => 'success', 'msg' => "Berhasil menghapus {$result['deleted']} post spam."];
    }

    private function dbDeleteOptions($ids)
    {
        if (empty($ids) || !is_array($ids)) {
            throw new Exception("Tidak ada option yang dipilih.");
        }
        $siteId = isset($_POST['site_id']) ? intval($_POST['site_id']) : null;
        $scanner = $this->getDBScanner($siteId);
        $result = $scanner->deleteSuspiciousOptions($ids);
        if ($result['status'] === 'error') {
            throw new Exception($result['msg']);
        }
        return ['status' => 'success', 'msg' => "Berhasil menghapus {$result['deleted']} option mencurigakan."];
    }

    private function dbDeleteUsers($ids)
    {
        if (empty($ids) || !is_array($ids)) {
            throw new Exception("Tidak ada user yang dipilih.");
        }
        $siteId = isset($_POST['site_id']) ? intval($_POST['site_id']) : null;
        $scanner = $this->getDBScanner($siteId);
        $result = $scanner->deleteSuspiciousUsers($ids);
        if ($result['status'] === 'error') {
            throw new Exception($result['msg']);
        }
        return ['status' => 'success', 'msg' => "Berhasil menghapus {$result['deleted']} user."];
    }

    private function dbDeleteRedirects($ids)
    {
        if (empty($ids) || !is_array($ids)) {
            throw new Exception("Tidak ada item yang dipilih.");
        }
        $siteId = isset($_POST['site_id']) ? intval($_POST['site_id']) : null;
        $scanner = $this->getDBScanner($siteId);
        $result = $scanner->deleteRedirectInjections($ids);
        if ($result['status'] === 'error') {
            throw new Exception($result['msg']);
        }
        return ['status' => 'success', 'msg' => "Berhasil menghapus {$result['deleted']} redirect injection."];
    }

}

// ---------------------------------------------------------
// APP EXECUTION
// ---------------------------------------------------------
$auth = new RadarAuth();
$authError = $auth->handle();

$detector = new RadarDetector();
$scanner = new RadarScanner($detector->siteRoot);
$actions = new RadarActions($detector);

if (isset($_POST['action'])) {
    // HARDENING: Aggressive output cleaning
    while (ob_get_level()) {
        ob_end_clean();
    }
    ob_start(); // Start fresh buffer using default handler
    error_reporting(0);
    @ini_set('display_errors', 0);
    header('Content-Type: application/json');
    try {
        echo json_encode($actions->handle($_POST['action']));
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'msg' => $e->getMessage()]);
    } catch (Throwable $t) {
        echo json_encode(['status' => 'error', 'msg' => $t->getMessage()]);
    }
    exit;
}

// UI Rendering Logic for Dynamic Navigation
$base = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]" . dirname($_SERVER['PHP_SELF']);
$xtool_url = $base . '/xtool.php';
$bantuan_url = $base . '/bantuan.php';
?>
<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>RadarKit v4.5 | Professional Malware Guard</title>
    <link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-grad: linear-gradient(90deg, #1c2429, #263238);
            --bg-deep: #263238;
            --accent: #ff8c00;
            --text-color: #FFFFFF;
            --text-muted: #CFD8DC;
            --border-color: rgba(255, 255, 255, 0.08);
        }

        html,
        body {
            height: 100%;
            -webkit-font-smoothing: antialiased;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-grad);
            color: var(--text-color);
            font-size: 14px;
        }

        .navbar {
            background-color: var(--bg-deep);
            border-bottom: 1px solid var(--border-color);
            padding: 0.5rem 1rem;
        }

        .navbar-brand {
            font-weight: 600;
            font-size: 1.1rem;
            color: var(--accent) !important;
        }

        .card {
            background-color: var(--bg-deep);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .card-header {
            background-color: rgba(0, 0, 0, 0.25);
            border-bottom: 1px solid var(--border-color);
            padding: 0.75rem 1.25rem;
            font-weight: 600;
            color: var(--accent);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .table {
            color: #ddd;
            margin-bottom: 0;
        }

        .table thead th {
            background-color: rgba(0, 0, 0, 0.3);
            border-bottom: 2px solid var(--border-color);
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .table td {
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            vertical-align: middle;
        }

        .btn-primary {
            background-color: var(--accent);
            border-color: var(--accent);
            color: #000;
            font-weight: 600;
        }

        .btn-primary:hover {
            background-color: #e67e00;
            border-color: #e67e00;
            color: #000;
        }

        .badge-score {
            font-family: 'Courier New', monospace;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            padding: 2px 6px;
            border-radius: 4px;
        }

        .factor {
            font-size: 0.7rem;
            padding: 2px 5px;
            border-radius: 3px;
            margin-right: 3px;
            display: inline-block;
            margin-bottom: 2px;
        }

        .f-danger {
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .f-warning {
            background: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }

        .f-info {
            background: rgba(59, 130, 246, 0.2);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }

        #overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.85);
            z-index: 9999;
            padding: 2rem;
        }

        #overlay-content {
            background: #1e1e1e;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            height: 100%;
            display: flex;
            flex-direction: column;
        }

        #overlay-body {
            flex: 1;
            overflow: auto;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            display: flex;
        }

        .gutter {
            background: #252525;
            color: #858585;
            padding: 10px;
            text-align: right;
            min-width: 45px;
            border-right: 1px solid #333;
            user-select: none;
        }

        .code-area {
            padding: 10px;
            flex: 1;
            white-space: pre;
        }

        .hl-danger {
            color: #f87171;
            font-weight: bold;
            background: rgba(239, 68, 68, 0.1);
        }

        .hl-warning {
            color: #fbbf24;
        }

        /* Phase 9: Smart Malware Highlighting */
        .hl-malicious {
            background: rgba(239, 68, 68, 0.4);
            border-bottom: 1px dotted #ff0000;
            color: #fff;
            font-weight: bold;
            display: inline-block;
            padding: 0 2px;
            border-radius: 2px;
        }

        #scan-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            z-index: 10000;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        .scan-modal {
            background: rgba(30, 39, 46, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 20px;
            padding: 3rem;
            width: 400px;
            text-align: center;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }

        .pulse-container {
            position: relative;
            width: 100px;
            height: 100px;
            margin: 0 auto 30px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .pulse-ring {
            position: absolute;
            width: 80px;
            height: 80px;
            border: 2px solid var(--accent);
            border-radius: 50%;
            opacity: 0;
            animation: pulse-ring 2s cubic-bezier(0.21, 0.53, 0.56, 0.8) infinite;
        }

        .pulse-core {
            font-size: 3rem;
            color: var(--accent);
            position: relative;
            z-index: 1;
        }

        @keyframes pulse-ring {
            0% {
                transform: scale(0.5);
                opacity: 0;
            }

            50% {
                opacity: 0.5;
            }

            100% {
                transform: scale(1.6);
                opacity: 0;
            }
        }

        .loader-box {
            width: 100%;
            background: rgba(255, 255, 255, 0.05);
            height: 6px;
            border-radius: 3px;
            overflow: hidden;
            margin: 25px 0 10px;
        }

        .loader-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, var(--accent), #ffa726);
            box-shadow: 0 0 15px var(--accent);
            transition: width 0.4s cubic-bezier(0.1, 0, 0.3, 1);
        }

        @keyframes grow {
            0% {
                width: 0%;
            }

            5% {
                width: 15%;
            }

            45% {
                width: 65%;
            }

            100% {
                width: 98%;
            }
        }

        @keyframes rotation {
            0% {
                transform: rotate(0deg);
            }

            100% {
                transform: rotate(360deg);
            }
        }

        .spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: rotation 0.8s linear infinite;
        }

        .btn-icon {
            padding: 0.25rem 0.5rem;
            line-height: 1;
        }

        .text-accent {
            color: var(--accent) !important;
        }

        /* Pagination Styling */
        .pagination-container {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 0.5rem;
            margin-top: 1rem;
            padding: 0.5rem;
            border-top: 1px solid var(--border-color);
        }

        .pg-btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.75rem;
            transition: all 0.2s;
        }

        .pg-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-color);
        }

        .pg-btn.active {
            background: var(--accent);
            color: #000;
            border-color: var(--accent);
            font-weight: 600;
        }

        .pg-btn:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }
    </style>
    <!-- PDF Export Libraries (V9) -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.25/jspdf.plugin.autotable.min.js"></script>
</head>

<body>
    <nav class="navbar navbar-expand-lg border-bottom px-3 py-2 sticky-top">
        <div class="container-fluid">
            <a class="navbar-brand d-flex align-items-center" href="radar.php">
                <i class="fa fa-shield me-2"></i><span>RadarKit <span class="fw-light opacity-50">v4.5</span></span>
            </a>
            <div class="d-flex align-items-center gap-2">
                <div class="btn-group btn-group-sm me-2">
                    <a href="<?php echo $xtool_url ?>" target="_blank"
                        class="btn btn-outline-warning border-black border-opacity-10 py-1"
                        title="Buka File Manager (XTool)">
                        <i class="fa fa-folder-open me-1"></i> XTool
                    </a>
                    <a href="<?php echo $bantuan_url ?>" target="_blank"
                        class="btn btn-outline-info border-black border-opacity-10 py-1" title="Buka Database Bridge">
                        <i class="fa fa-database me-1"></i>Database
                    </a>
                </div>
                <div class="border-start border-white border-opacity-25 ps-3 py-1 ms-1">
                    <a href="?logout=1" class="text-danger text-decoration-none small fw-bold">
                        <i class="fa fa-sign-out me-1"></i>Logout
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <div class="container py-3">
        <div class="row g-3">
            <!-- Core & Baseline Info -->
            <div class="col-md-6">
                <div class="card h-100">
                    <div class="card-header">
                        <div><i class="fa fa-heartbeat me-2"></i>Core Baseline System</div>
                    </div>
                    <div class="card-body">
                        <?php
                        $fv_path = __DIR__ . '/fresh_core/wp-includes/version.php';
                        $fv = 'None';
                        if (file_exists($fv_path)) {
                            $c = file_get_contents($fv_path);
                            if (preg_match('/\$wp_version\s*=\s*[\'"](.+?)[\'"]\s*;/', $c, $m))
                                $fv = $m[1];
                        }
                        $sync = ($fv === $detector->wpVersion);
                        ?>
                        <div class="d-flex justify-content-between align-items-start mb-3">
                            <div>
                                <div class="small fw-bold text-white mb-1 uppercase" style="letter-spacing: 0.05rem;">WP
                                    Version Status</div>
                                <div class="h5 mb-0 fw-bold">
                                    <span class="text-accent">v<?php echo $detector->wpVersion; ?></span>
                                    <?php echo $sync ? '<span class="text-success ms-2" style="font-size:0.8rem"><i class="fa fa-check-circle"></i> Baseline Ready</span>' : '<span class="text-danger ms-2" style="font-size:0.8rem"><i class="fa fa-times-circle"></i> Out of Sync</span>'; ?>
                                </div>
                            </div>
                            <div class="text-end">
                                <div class="small fw-bold text-white mb-1 uppercase" style="letter-spacing: 0.05rem;">
                                    Baseline</div>
                                <span class="badge bg-success bg-opacity-75 text-white"
                                    style="font-size:0.75rem">v<?php echo $fv; ?></span>
                            </div>
                        </div>

                        <?php if ($detector->wpConfig['is_multisite']): ?>
                            <div class="mb-3">
                                <span class="badge bg-info bg-opacity-25 text-info border border-info border-opacity-25"
                                    style="font-size:0.7rem">
                                    <i class="fa fa-sitemap me-1"></i>MULTISITE
                                    (<?php echo count($detector->wpConfig['sites']); ?> sites)
                                </span>
                            </div>
                        <?php endif; ?>

                        <div class="p-2 bg-black bg-opacity-25 rounded border border-white-10 mb-3">
                            <span class="logo-text">RADAR <small>v4.5</small></span>
                            <small class="text-muted d-block small-xs mb-1">DETECTED ROOT PATH</small>
                            <code class="text-warning small"><?php echo htmlspecialchars($detector->siteRoot); ?></code>
                        </div>

                        <div class="d-grid gap-2">
                            <?php if (!$sync && $detector->wpVersion !== 'Unknown'): ?>
                                <button
                                    onclick="apiCall(this, 'sync_core', {version:'<?php echo $detector->wpVersion; ?>'})"
                                    class="btn btn-primary btn-sm">
                                    <i class="fa fa-refresh me-2"></i>Sync v<?php echo $detector->wpVersion; ?> Baseline
                                </button>
                            <?php endif; ?>
                            <?php if ($sync): ?>
                                <button onclick="apiCall(this, 'replace_core')"
                                    class="btn btn-primary btn-sm btn-info text-white border-0"
                                    style="background-image: linear-gradient(180deg, #3b82f6, #2563eb);">
                                    <i class="fa fa-bolt me-2"></i>Operasi Jantung (Safe Replace)
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Admin Audit -->
            <div class="col-md-6">
                <div class="card h-100">
                    <div class="card-header">
                        <div><i class="fa fa-users me-2"></i>Admin Audit</div>
                        <?php if ($detector->dbConn): ?>
                            <span class="badge bg-opacity-10 bg-info text-info border border-info border-opacity-25"
                                style="font-size:0.6rem">DATABASE CONNECTED</span>
                        <?php endif; ?>
                    </div>
                    <?php if ($detector->dbConn): ?>
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-sm table-dark mb-0" id="adminAuditTable">
                                    <thead>
                                        <tr>
                                            <th class="ps-3">User</th>
                                            <th>Email</th>
                                            <th class="text-center">Risk</th>
                                        </tr>
                                    </thead>
                                    <tbody id="adminAuditBody">
                                        <?php
                                        // Multisite: query admin dari SEMUA sub-sites
                                        if ($detector->wpConfig['is_multisite'] && !empty($detector->wpConfig['sites'])) {
                                            $capKeys = array_map(fn($s) => "'{$s['prefix']}capabilities'", $detector->wpConfig['sites']);
                                            $capIn = implode(',', $capKeys);
                                            $sql = "SELECT DISTINCT ID, user_login, user_email FROM {$detector->wpConfig['prefix']}users WHERE ID IN (SELECT user_id FROM {$detector->wpConfig['prefix']}usermeta WHERE meta_key IN ({$capIn}) AND meta_value LIKE '%administrator%')";
                                        } else {
                                            $sql = "SELECT ID, user_login, user_email FROM {$detector->wpConfig['prefix']}users WHERE ID IN (SELECT user_id FROM {$detector->wpConfig['prefix']}usermeta WHERE meta_key = '{$detector->wpConfig['prefix']}capabilities' AND meta_value LIKE '%administrator%')";
                                        }
                                        $admins = $detector->dbConn->query($sql)->fetchAll();
                                        foreach ($admins as $index => $r):
                                            $w = !preg_match('/@gmail\.com|@yahoo\.com|@' . str_replace('www.', '', $_SERVER['HTTP_HOST'] ?? '') . '/i', $r['user_email']);
                                            ?>
                                            <tr class="admin-row bg-black bg-opacity-10" data-index="<?php echo $index; ?>">
                                                <td class="ps-3 py-2">
                                                    <i class="fa fa-user-circle-o me-2 text-white-50"></i>
                                                    <strong class="text-white"><?php echo $r['user_login'] ?></strong>
                                                </td>
                                                <td class="small text-white-75 py-2"><?php echo $r['user_email'] ?></td>
                                                <td class="text-center py-2">
                                                    <?php echo $w ? '<span class="badge bg-danger text-white border border-danger border-opacity-50" style="font-size:0.65rem">HIGH RISK</span>' : '<span class="badge bg-success text-white border border-success border-opacity-50" style="font-size:0.65rem">LOW RISK</span>' ?>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                            <div id="adminAuditPagination" class="pagination-container py-2"
                                style="background: rgba(0,0,0,0.1)"></div>
                        </div>
                    <?php else: ?>
                        <div
                            class="card-body d-flex flex-column justify-content-center align-items-center text-center opacity-50 py-5">
                            <i class="fa fa-database fa-3x mb-3"></i>
                            <p class="mb-0">Database error or not connected.</p>
                            <small
                                class="text-warning"><?php echo htmlspecialchars($detector->wpConfig['db_error'] ?? 'Unknown Error'); ?></small>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <?php if (!empty($detector->wpConfig['db_error'])): ?>
            <div class="alert alert-danger d-flex align-items-center mt-4 border-0 bg-danger bg-opacity-10 text-danger"
                role="alert">
                <i class="fa fa-exclamation-triangle fa-2x me-3"></i>
                <div>
                    <strong>Database Connection Failed!</strong><br>
                    <small class="font-monospace"><?php echo htmlspecialchars($detector->wpConfig['db_error']); ?></small>
                </div>
            </div>
        <?php endif;

        function renderFactors($s)
        {
            $f = explode(', ', $s);
            $out = '';
            foreach ($f as $v) {
                $cls = 'f-info';
                if (preg_match('/eval|shell_exec|Slang/i', $v))
                    $cls = 'f-danger';
                elseif (preg_match('/base64|Entropy/i', $v))
                    $cls = 'f-warning';
                $out .= "<span class='factor $cls'>$v</span>";
            }
            return $out;
        }
        ?>

        <!--  Database Scanner -->
        <?php if ($detector->dbConn): ?>
            <div class="card shadow-sm mt-3">
                <div class="card-header">
                    <h5 class="mb-0 fs-6 fw-bold text-accent">
                        <i class="fa fa-database me-2"></i>Database Scanner
                    </h5>
                    <div class="d-flex align-items-center gap-2">
                        <?php if ($detector->wpConfig['is_multisite'] && !empty($detector->wpConfig['sites'])): ?>
                            <select id="dbSiteSelectorDropdown"
                                class="form-select form-select-sm bg-dark text-white border-secondary"
                                style="width:auto; font-size:0.75rem;">
                                <?php foreach ($detector->wpConfig['sites'] as $site): ?>
                                    <option value="<?= $site['blog_id'] ?>">
                                        Site #<?= $site['blog_id'] ?> &mdash;
                                        <?= htmlspecialchars($site['domain'] . $site['path']) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        <?php endif; ?>
                        <button onclick="startDBScan()" class="btn btn-primary btn-sm px-3" id="btnDBScan">
                            <i class="fa fa-play me-1"></i>Scan Database
                        </button>
                    </div>
                </div>
                <div class="card-body p-0" id="dbScanResultsContainer" style="display:none;">
                    <!-- Tabs & Actions Wrapper (v4.7.2) -->
                    <div
                        class="d-flex justify-content-between align-items-center bg-black bg-opacity-10 px-3 border-bottom border-white-10">
                        <ul class="nav nav-tabs border-0 pt-2" id="dbScanTabs" role="tablist">
                            <li class="nav-item" role="presentation">
                                <button
                                    class="nav-link active bg-transparent text-white border-0 border-bottom border-2 border-accent px-3 py-2"
                                    id="tab-posts" data-bs-toggle="tab" data-bs-target="#panel-posts" type="button"
                                    role="tab">
                                    <i class="fa fa-file-text-o me-1"></i>Posts <span class="badge bg-danger"
                                        id="badge-posts">0</span>
                                </button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link bg-transparent text-white-50 border-0 px-3 py-2" id="tab-options"
                                    data-bs-toggle="tab" data-bs-target="#panel-options" type="button" role="tab">
                                    <i class="fa fa-cog me-1"></i>Options <span class="badge bg-warning text-dark"
                                        id="badge-options">0</span>
                                </button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link bg-transparent text-white-50 border-0 px-3 py-2" id="tab-users"
                                    data-bs-toggle="tab" data-bs-target="#panel-users" type="button" role="tab">
                                    <i class="fa fa-users me-1"></i>Users <span class="badge bg-info"
                                        id="badge-users">0</span>
                                </button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link bg-transparent text-white-50 border-0 px-3 py-2" id="tab-redirects"
                                    data-bs-toggle="tab" data-bs-target="#panel-redirects" type="button" role="tab">
                                    <i class="fa fa-external-link me-1"></i>Redirects <span class="badge bg-danger"
                                        id="badge-redirects">0</span>
                                </button>
                            </li>
                        </ul>
                        <div class="py-2">
                            <button onclick="dbBulkDelete()" class="btn btn-danger btn-sm px-3" id="btnDBBulkDelete"
                                disabled title="Hapus temuan terpilih sekaligus">
                                <i class="fa fa-trash me-2"></i>Hapus Terpilih (<span id="dbSelectedCount">0</span>)
                            </button>
                        </div>
                    </div>

                    <!-- Tab Content -->
                    <!-- Tab Content -->
                    <div class="tab-content bg-black bg-opacity-10 rounded-bottom" id="dbScanTabContent">
                        <!-- Posts Panel -->
                        <div class="tab-pane fade show active p-3" id="panel-posts" role="tabpanel">
                            <div id="dbPostsResults" class="text-white-50 ">Klik "Scan Database" untuk memulai
                                pencarian spam...</div>
                        </div>
                        <!-- Options Panel -->
                        <div class="tab-pane fade p-3" id="panel-options" role="tabpanel">
                            <div id="dbOptionsResults" class="text-white-50">Klik "Scan Database" untuk memulai
                                pencarian spam...</div>
                        </div>
                        <!-- Users Panel -->
                        <div class="tab-pane fade p-3" id="panel-users" role="tabpanel">
                            <div id="dbUsersResults" class="text-white-50">Klik "Scan Database" untuk memulai
                                pencarian spam...</div>
                        </div>
                        <!-- Redirects Panel -->
                        <div class="tab-pane fade p-3" id="panel-redirects" role="tabpanel">
                            <div id="dbRedirectsResults" class="text-white-50">Klik "Scan Database" untuk memulai
                                pencarian spam...</div>
                        </div>
                    </div>
                </div>
                <div id="dbScanPlaceholder">
                    <div class="card-body p-3 bg-black bg-opacity-10 rounded-bottom">
                        <div class="text-center py-5 bg-black bg-opacity-10 rounded">
                            <i class="fa fa-database fa-4x mb-3 text-white" style="opacity: 0.6;"></i>
                            <p class="h5 mb-2 text-white">Database Standby</p>
                            <p class="text-white-50 small px-5">Klik tombol <strong>Scan Database</strong> untuk memeriksa
                                wp_posts, wp_options, dan wp_users</p>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <!-- Smart Heuristic Analysis -->
        <div class="card shadow-sm mt-3 mb-5">
            <div class="card-header">
                <h5 class="mb-0 fs-6 fw-bold text-accent">
                    <i class="fa fa-search me-2"></i>Smart Heuristic Analysis
                    <span id="fileScanPath" class="ms-3 small fw-normal text-white-50"></span>
                    <span id="fileScanSummary" class="ms-2"></span>
                </h5>
                <div>
                    <button onclick="startDeepScan()" class="btn btn-primary btn-sm px-3" id="btnDeepScan">
                        <i class="fa fa-play me-2"></i>Deep Scan
                    </button>
                    <button type="button" onclick="clearScanCache()" class="btn btn-outline-secondary btn-sm ms-1"
                        title="Clear Cache">
                        <i class="fa fa-refresh"></i>
                    </button>
                </div>
            </div>

            <!-- Results Card (always rendered, visibility controlled by JS) -->
            <div id="scanResultsCard" style="display: none;">
                <div class="card-body bg-black bg-opacity-10 p-3 border-bottom border-white-10">
                    <div class="row g-2 align-items-center">
                        <div class="col-md-3">
                            <select id="filterSeverity" onchange="filterResults()"
                                class="form-select form-select-sm bg-dark text-white border-white-10">
                                <option value="">Semua Severity</option>
                                <option value="CRITICAL">🔴 CRITICAL ONLY</option>
                                <option value="SUSPICIOUS">🟡 SUSPICIOUS ONLY</option>
                            </select>
                        </div>
                        <div class="col-md-auto">
                            <button onclick="sortByScore()" class="btn btn-outline-secondary btn-sm border-white-10">
                                <i class="fa fa-sort-amount-desc me-1"></i>Sort by Score
                            </button>
                            <button onclick="exportResults()" class="btn btn-outline-info btn-sm border-white-10 ms-1"
                                id="btnExportPDF" disabled title="Lakukan Scan File & Database untuk mengunduh laporan">
                                <i class="fa fa-file-pdf-o me-1"></i>Export PDF Report
                            </button>
                        </div>
                        <div class="col-md text-end">
                            <button onclick="bulkDeleteSelected()" class="btn btn-danger btn-sm px-3" id="bulkDeleteBtn"
                                disabled title="Hapus file terpilih sekaligus">
                                <i class="fa fa-trash me-2"></i>Hapus Terpilih (<span id="selectedCount">0</span>)
                            </button>
                        </div>
                    </div>
                </div>
                <div class="card-body p-0 bg-black bg-opacity-10 rounded-bottom">
                    <div id="fileScanResultsArea" class="p-3" style="display:none;">
                        <div class="table-responsive">
                            <table id="scanResultsTable" class="table table-sm table-dark align-middle mb-0">
                                <thead>
                                    <tr>
                                        <th class="ps-3" style="width: 45px;"><input type="checkbox" id="selectAll"
                                                class="form-check-input" onchange="toggleSelectAll()"></th>
                                        <th style="width: 100px;">TINGKAT</th>
                                        <th style="width: 80px;" class="text-center">SKOR</th>
                                        <th>JALUR TERDETEKSI</th>
                                        <th>FAKTOR HEURISTIK</th>
                                        <th class="text-end pe-3" style="width: 100px;">AKSI</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <!-- Results rendered by JavaScript -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Standby Card (visibility controlled by JS) -->
            <div id="scannerStandby">
                <div class="card-body p-3 bg-black bg-opacity-10 rounded-bottom">
                    <div class="text-center py-5 bg-black bg-opacity-10 rounded">
                        <i class="fa fa-crosshairs fa-4x mb-3 text-white" style="opacity: 0.6;"></i>
                        <p class="h5 mb-2 text-white">Scanner Standby</p>
                        <p class="text-white-50 small px-5">Klik tombol <strong>Deep Scan</strong> untuk memulai
                            pencarian malware pada Root Directory.</p>
                    </div>
                </div>
            </div>
        </div>
    </div> <!-- Close Container -->

    <!-- File Inspection Overlay -->
    <div id="overlay">
        <div id="overlay-content">
            <div class="card-header border-bottom d-flex justify-content-between align-items-center py-2 bg-dark">
                <div class="small fw-light"><i class="fa fa-code me-2"></i>File Inspector</div>
                <button onclick="document.getElementById('overlay').style.display='none'"
                    class="btn btn-sm btn-link text-white-50 p-0 text-decoration-none">
                    <i class="fa fa-times fa-lg"></i>
                </button>
            </div>
            <div id="overlay-body"></div>
        </div>
    </div>

    <!-- Scan Progress Overlay -->
    <div id="scan-overlay">
        <div class="scan-modal">
            <div class="pulse-container">
                <div class="pulse-ring"></div>
                <div class="pulse-ring" style="animation-delay: 1s;"></div>
                <i class="fa fa-crosshairs pulse-core"></i>
            </div>
            <h4 id="scan-title" class="text-white mb-2 fw-bold">Radar Scanning...</h4>
            <p id="scan-desc" class="text-white-50 small mb-0">Analyzing filesystem. Please wait.</p>
            <div class="loader-box">
                <div class="loader-fill"></div>
            </div>
        </div>
    </div>

    <script>
        // SessionStorage Keys
        const STORAGE_KEY_FILES = 'radar_file_scan';
        const STORAGE_KEY_DB = 'radar_db_scan';

        // Save scan results to sessionStorage
        function saveScanResults(key, data) {
            sessionStorage.setItem(key, JSON.stringify({
                timestamp: Date.now(),
                data: data
            }));
        }

        // Load scan results from sessionStorage
        function loadScanResults(key) {
            const cached = sessionStorage.getItem(key);
            if (cached) {
                return JSON.parse(cached);
            }
            return null;
        }

        // v9.0: Dynamic Button State Logic
        function updateExportButtonState() {
            const btn = document.getElementById('btnExportPDF');
            if (!btn) return;

            const fileScan = loadScanResults(STORAGE_KEY_FILES);
            const dbScan = loadScanResults(STORAGE_KEY_DB);

            const hasFiles = fileScan && fileScan.data && Array.isArray(fileScan.data.results);
            const hasDB = dbScan && dbScan.data && dbScan.data.summary;

            if (hasFiles && hasDB) {
                btn.disabled = false;
                btn.classList.replace('btn-outline-info', 'btn-info');
                btn.title = "Unduh Laporan PDF Lengkap (File + Database)";
            } else {
                btn.disabled = true;
                btn.classList.replace('btn-info', 'btn-outline-info');
                let missing = [];
                if (!hasFiles) missing.push("File Scanner");
                if (!hasDB) missing.push("Database Scanner");
                btn.title = "Lengkapi Scan berikut: " + missing.join(" & ");
            }
        }

        // Format timestamp for display
        function formatTimestamp(ts) {
            const date = new Date(ts);
            return date.toLocaleString('id-ID')
                ;


        }

        /**
        * v4.6: Gl        obal Pagination Helper
        * Renders pagina        tion buttons into a container.
        */
        function renderPagination(containerId, totalItems, itemsPerPage, currentPage, onPageChange) {
            const container = document.getElementById(containerId);
            if (!container) return;

            const totalPages = Math.ceil(totalItems / itemsPerPage);
            if (totalPages <= 1) {
                container.innerHTML = '';
                return;
            }

            let html = `<button class="pg-btn" ${currentPage === 1 ? 'disabled' : ''} onclick="${onPageChange}(${currentPage - 1})"><i class="fa fa-chevron-left"></i></button>`;

            for (let i = 1; i <= totalPages; i++) {
                if (totalPages > 7) {
                    if (i > 2 && i < totalPages - 1 && Math.abs(i - currentPage) > 1) {
                        if (i === 3 || i === totalPages - 2) html += '<span class="text-white-50 mx-1">...</span>';
                        continue;
                    }
                }
                html += `<button class="pg-btn ${i === currentPage ? 'active' : ''}" onclick="${onPageChange}(${i})">${i}</button>`;
            }

            html += `<button class="pg-btn" ${currentPage === totalPages ? 'disabled' : ''} onclick="${onPageChange}(${currentPage + 1})"><i class="fa fa-chevron-right"></i></button>`;

            container.innerHTML = html;
        }

        // AJAX-based Deep Scan (no page reload)
        async function startDeepScan() {
            const startTime = Date.now();
            setProgress(0); // Reset progress

            const overlay = document.getElementById('scan-overlay');
            const btn = document.getElementById('btnDeepScan');
            const title = document.getElementById('scan-title');
            const desc = document.getElementById('scan-desc');

            if (title) title.innerText = 'Radar Scanning...';
            if (desc) desc.innerText = 'Analyzing filesystem. Please wait.';

            if (overlay) overlay.style.display = 'flex';
            if (btn) btn.disabled = true;

            // v4.5: Progress Simulation (0 to 90%)
            const progInt = setInterval(() => {
                const elapsed = Date.now() - startTime;
                const progress = Math.min(90, (elapsed / 2000) * 90);
                setProgress(progress);
            }, 100);

            try {
                const res = await sendRequest('file_scan', {});

                // Snap to 100% once done
                clearInterval(progInt);
                setProgress(100);

                if (res.status === 'success' && res.data) {
                    // Save to sessionStorage
                    saveScanResults(STORAGE_KEY_FILES, res.data);

                    // Render results
                    renderFileScanResults(res.data);
                    // v9.0: Update button state
                    updateExportButtonState();
                } else {
                    alert('Scan Gagal: ' + (res.msg || 'Terjadi kesalahan sistem.'));
                }
            } catch (e) {
                clearInterval(progInt);
                alert('Error: ' + e.message);
            } finally {
                // v4.5: Professional Duration (Min 2000ms)
                const elapsed = Date.now() - startTime;
                if (elapsed < 2000) await sleep(2000 - elapsed);

                // Extra brief wait to let them see 100%
                await sleep(300);

                if (overlay) overlay.style.display = 'none';
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fa fa-refresh me-1"></i>Re-Scan';
                }
            }
        }

        // Render file scan results
        // v4.6: Added pagination support (Max 10)
        function renderFileScanResults(data, page = 1) {
            const container = document.getElementById('fileScanResultsArea');
            const standby = document.getElementById('scannerStandby');
            const resultsCard = document.getElementById('scanResultsCard');

            if (standby) standby.style.display = 'none';
            if (resultsCard) resultsCard.style.display = 'block';
            if (container) container.style.display = 'block';

            if (data.root) {
                const pathBadge = document.getElementById('fileScanPath');
                if (pathBadge) pathBadge.innerHTML = `[Path: ${escapeHtml(data.root)}]`;
            }

            if (!data.results || data.results.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-5 bg-black bg-opacity-10 rounded">
                        <i class="fa fa-check-circle fa-4x text-success mb-3" style="opacity:0.6"></i>
                        <p class="h5 text-success mb-2">Direktori utama terlihat bersih!</p>
                        <p class="text-white-50 small mb-0">Tidak ada pola mencurigakan atau malware yang terdeteksi dalam pemindaian ini.</p>
                    </div>`;
                return;
            }

            // If has results, restore the table structure
            container.innerHTML = `<div class="table-responsive">
                <table id="scanResultsTable" class="table table-sm table-dark align-middle mb-0">
                    <thead>
                        <tr>
                            <th class="ps-3" style="width: 45px;"><input type="checkbox" id="selectAll" class="form-check-input" onchange="toggleSelectAll()"></th>
                            <th style="width: 100px;">TINGKAT</th>
                            <th style="width: 80px;" class="text-center">SKOR</th>
                            <th>JALUR TERDETEKSI</th>
                            <th>FAKTOR HEURISTIK</th>
                            <th class="text-end pe-3" style="width: 100px;">AKSI</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
            <div id="fileScanPagination" class="pagination-container"></div>`;

            const tbody = container.querySelector('tbody');
            const itemsPerPage = 10;
            const sorted = data.results.sort((a, b) => b.score - a.score);

            // Slice data for pagination
            const start = (page - 1) * itemsPerPage;
            const end = start + itemsPerPage;
            const pagedItems = sorted.slice(start, end);

            let html = '';
            pagedItems.forEach(t => {
                const rowId = 'row-' + b64EncodeUnicode(t.path).replace(/[^a-zA-Z0-9]/g, '').substr(0, 16);
                const b64p = b64EncodeUnicode(t.path);
                const sevClass = t.severity === 'CRITICAL' ? 'bg-danger' : 'bg-warning text-dark';

                const factors = t.reason.split(', ').map(r => {
                    const cls = r.includes('eval') || r.includes('Backdoor') ? 'f-danger' : 'f-warning';
                    return `<span class="factor ${cls}">${escapeHtml(r)}</span>`;
                }).join('');

                html += `<tr id="${rowId}" data-severity="${t.severity}" data-score="${t.score}" data-path="${b64p}">
                    <td class="ps-3"><input type="checkbox" class="form-check-input row-select" onchange="updateSelectedCount()"></td>
                    <td><span class="badge ${sevClass}" style="font-size:0.6rem">${t.severity}</span></td>
                    <td class="text-center"><span class="badge-score small">${t.score}</span></td>
                    <td class="small font-monospace text-truncate" style="max-width: 400px;">
                        <span title="${escapeHtml(t.path)}">${escapeHtml(t.rel_path)}</span>
                    </td>
                    <td class="small">${factors}</td>
                    <td class="text-end pe-3">
                        <button class="btn btn-sm btn-outline-secondary me-1" onclick="viewFile('${b64p}')" title="View">
                            <i class="fa fa-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteFiles([b64DecodeUnicode('${b64p}')], this)" title="Delete">
                            <i class="fa fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            });

            tbody.innerHTML = html;

            // Render pagination controls
            renderPagination('fileScanPagination', data.results.length, itemsPerPage, page, 'changeFileScanPage');

            // Update summary badge if exists
            updateFileScanSummary(data.summary);
        }

        // v4.7.2: Generic delete handler for individual files
        async function deleteFiles(paths, btn) {
            if (!confirm('Hapus ' + paths.length + ' file terpilih?')) return;

            const res = await sendRequest('bulk_delete', { paths: JSON.stringify(paths) }, btn);
            if (res.msg) alert(res.msg);

            if (res.status === 'success') {
                // Sync Cache
                const cached = loadScanResults(STORAGE_KEY_FILES);
                if (cached && cached.data && cached.data.results) {
                    cached.data.results = cached.data.results.filter(r => !paths.includes(r.path));
                    cached.data.summary.total = cached.data.results.length;
                    cached.data.summary.critical = cached.data.results.filter(r => r.severity === 'CRITICAL').length;
                    cached.data.summary.suspicious = cached.data.results.filter(r => r.severity === 'SUSPICIOUS').length;
                    saveScanResults(STORAGE_KEY_FILES, cached.data);
                }
                location.reload();
            }
        }

        // v4.6: File Scan Page Change Handler
        function changeFileScanPage(page) {
            const cached = loadScanResults(STORAGE_KEY_FILES);
            if (cached && cached.data) {
                renderFileScanResults(cached.data, page);
            }
        }

        // Update summary display
        function updateFileScanSummary(summary) {
            const badge = document.getElementById('fileScanSummary');
            if (badge && summary) {
                badge.innerHTML = `<span class="badge bg-danger bg-opacity-10 text-danger border border-danger border-opacity-25" style="font-size:0.65rem">${summary.critical}</span> 
                                   <span class="badge bg-warning bg-opacity-10 text-warning border border-warning border-opacity-25 ms-1" style="font-size:0.65rem">${summary.suspicious}</span>`;
            }
        }

        // Reset all scan states
        function clearScanCache() {
            try {
                console.log('Radar: Clearing scan cache...');
                if (!confirm('Hapus semua hasil scan tersimpan?')) return;
                sessionStorage.removeItem(STORAGE_KEY_FILES);
                sessionStorage.removeItem(STORAGE_KEY_DB);
                console.log('Radar: Cache cleared, reloading...');
                location.reload();
            } catch (e) {
                console.error('Radar Error: Failed to clear cache', e);
                alert('Gagal menghapus cache: ' + e.message);
            }
        }

        // Restore state on page load
        document.addEventListener('DOMContentLoaded', function () {
            try {
                console.log('DOMContentLoaded: Checking for cached scan results...');

                // Restore File Scan
                const fileScan = loadScanResults(STORAGE_KEY_FILES);
                if (fileScan && fileScan.data) {
                    console.log('Restoring file scan from:', formatTimestamp(fileScan.timestamp));
                    renderFileScanResults(fileScan.data);

                    // Update button to Re-Scan
                    const btn = document.getElementById('btnDeepScan');
                    if (btn) btn.innerHTML = '<i class="fa fa-refresh me-1"></i>Re-Scan';
                }

                // Restore DB Scan  
                const dbScan = loadScanResults(STORAGE_KEY_DB);
                if (dbScan && dbScan.data) {
                    console.log('Restoring DB scan from:', formatTimestamp(dbScan.timestamp));
                    restoreDBScanResults(dbScan.data);
                }

                // v5.0: Explicitly Enable Buttons (Prevent Deadlock)
                // v10.0: Only set 'Re-Scan' if cache actually exists. Otherwise use original labels.
                const btnDB = document.getElementById('btnDBScan');
                if (btnDB) {
                    btnDB.disabled = false;
                    if (dbScan && dbScan.data) {
                        btnDB.innerHTML = '<i class="fa fa-refresh me-1"></i>Re-Scan';
                    } else {
                        btnDB.innerHTML = '<i class="fa fa-play me-1"></i>Scan Database';
                    }
                }

                const btnFile = document.getElementById('btnDeepScan');
                if (btnFile) {
                    btnFile.disabled = false;
                    if (fileScan && fileScan.data) {
                        btnFile.innerHTML = '<i class="fa fa-refresh me-1"></i>Re-Scan';
                    } else {
                        btnFile.innerHTML = '<i class="fa fa-play me-2"></i>Deep Scan';
                    }
                }

                // v9.0: Initial State Check
                updateExportButtonState();

            } catch (e) {
                console.error('Radar Error: Critical failure during initialization', e);
                // Keep the 'Clear Cache' button functional if possible
            }
        });

        // Restore DB Scan results
        function restoreDBScanResults(data) {
            console.log('restoreDBScanResults called with:', data);

            const placeholder = document.getElementById('dbScanPlaceholder');
            const container = document.getElementById('dbScanResultsContainer');
            const btn = document.getElementById('btnDBScan');

            if (placeholder) placeholder.style.display = 'none';
            if (container) container.style.display = 'block';
            if (btn) btn.innerHTML = '<i class="fa fa-refresh me-1"></i>Re-Scan';

            // Update badges
            const postsCount = data.posts?.length || 0;
            const optionsCount = data.options?.length || 0;
            // v4.5.2: Only count actual users (ID > 0) for the badge
            const usersCount = (data.users || []).filter(u => u && u.id && u.id > 0).length;
            const redirectsCount = data.redirects?.length || 0;

            if (document.getElementById('badge-posts')) document.getElementById('badge-posts').textContent = postsCount;
            if (document.getElementById('badge-options')) document.getElementById('badge-options').textContent = optionsCount;
            if (document.getElementById('badge-users')) document.getElementById('badge-users').textContent = usersCount;
            if (document.getElementById('badge-redirects')) document.getElementById('badge-redirects').textContent = redirectsCount;

            // Render results
            renderDBPosts(data.posts || []);
            renderDBOptions(data.options || []);
            renderDBUsers(data.users || []);
            renderDBRedirects(data.redirects || []);
        }

        /**
         * v4.6: Admin Audit Pagination Logic
         */
        function changeAdminPage(page) {
            const rows = document.querySelectorAll('.admin-row');
            const itemsPerPage = 4;
            const start = (page - 1) * itemsPerPage;
            const end = start + itemsPerPage;

            rows.forEach((row, i) => {
                row.style.display = (i >= start && i < end) ? '' : 'none';
            });

            renderPagination('adminAuditPagination', rows.length, itemsPerPage, page, 'changeAdminPage');
        }

        // Initialize Admin Audit on load
        document.addEventListener('DOMContentLoaded', () => {
            const adminRows = document.querySelectorAll('.admin-row').length;
            if (adminRows > 0) changeAdminPage(1);
        });

        // --- Core Request Handler ---
        async function sendRequest(action, data = {}, btn = null) {
            let oldText = '';
            if (btn) {
                btn.disabled = true;
                oldText = btn.innerHTML; // Save HTML to preserve icons if any
                // Set explicit width to prevent collapse/jump
                btn.style.minWidth = btn.offsetWidth + 'px';
                btn.innerHTML = '<span class="spinner"></span>';
            }

            const formData = new URLSearchParams();
            formData.append('action', action);
            for (const key in data) {
                formData.append(key, data[key]);
            }

            try {
                const res = await fetch('radar.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: formData
                });

                const text = await res.text();
                let json;
                try {
                    json = JSON.parse(text);
                } catch (e) {
                    console.error("Server Raw:", text);
                    throw new Error("Server Error (Invalid JSON). Cek Console.");
                }

                return json;
            } catch (err) {
                alert('Connection Error: ' + err.message);
                return { status: 'error', msg: err.message };
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = oldText;
                }
            }
        }

        // --- Action Handlers ---

        async function viewFile(pathB64) {
            const body = document.getElementById('overlay-body');
            body.innerHTML = '<div style="padding:40px; text-align:center; color:#666"><i class="fa fa-circle-o-notch fa-spin fa-3x mb-3 text-muted"></i><br>Generating code preview...</div>';
            document.getElementById('overlay').style.display = 'block';

            // Phase 9: Get highlights from cache
            let highlights = [];
            const cached = loadScanResults(STORAGE_KEY_FILES);
            if (cached && cached.data && cached.data.results) {
                const targetPath = b64DecodeUnicode(pathB64);
                const fileEntry = cached.data.results.find(r => r.path === targetPath);
                if (fileEntry && fileEntry.highlights) {
                    highlights = fileEntry.highlights;
                }
            }

            // Send as target_b64
            const res = await sendRequest('view_file', { target_b64: pathB64 });
            if (res.status === 'success') {
                let gutter = '', code = '';
                const slang = ['gacor', 'maxwin', 'slot', 'JP', 'rungkad'];
                const danger = ['eval', 'shell_exec', 'system', 'passthru', 'base64_decode'];

                // Decode Base64 from server
                let content = '';
                try {
                    content = b64DecodeUnicode(res.data_b64);
                } catch (e) {
                    content = "Error decoding file content.";
                }

                const lines = content.split("\n");
                lines.forEach((line, i) => {
                    gutter += (i + 1) + '\n';
                    let escaped = line.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

                    // Phase 9: Smart Highlighting
                    if (highlights.length > 0) {
                        highlights.forEach(hl => {
                            if (hl.length > 2) { // Skip too short strings
                                try {
                                    // Escape special regex chars
                                    const pattern = hl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                                    escaped = escaped.replace(new RegExp('(' + pattern + ')', 'gi'), '<span class="hl-malicious">$1</span>');
                                } catch (e) { }
                            }
                        });
                    }

                    // Traditional Keyword Highlighting (Fallback)
                    danger.forEach(kw => { escaped = escaped.replace(new RegExp('(' + kw + ')', 'gi'), '<span class="hl-danger">$1</span>'); });
                    slang.forEach(kw => { escaped = escaped.replace(new RegExp('(' + kw + ')', 'gi'), '<span class="hl-warning">$1</span>'); });
                    code += escaped + '\n';
                });
                body.innerHTML = `<div class="gutter">${gutter}</div><div class="code-area">${code}</div>`;
            } else {
                body.innerHTML = `<div style="padding:40px; color:var(--danger)">Failed: ${res.msg}</div>`;
            }
        }

        // Handle: Delete
        async function runAction(btn, action, targetB64, rowId) {
            if (!confirm(btn.title + ' - Apakah anda yakin?')) return;

            // Send as target_b64
            const res = await sendRequest(action, { target_b64: targetB64 }, btn);
            alert(res.msg);

            if (res.status === 'success') {
                const tr = document.getElementById('row-' + rowId);
                if (tr) {
                    tr.style.transition = 'all 0.3s';
                    tr.style.opacity = '0.5';
                    tr.style.background = 'rgba(16, 185, 129, 0.05)';
                    tr.style.pointerEvents = 'none';
                    // Replace the action buttons (last column) with a nice status badge
                    const actionCell = tr.lastElementChild;
                    actionCell.innerHTML = `<span style="color:#ef4444; font-weight:bold; border:1px solid #ef444444; padding:2px 8px; border-radius:4px; display:inline-block; font-size: 0.65rem; background:#ef444411"><i class="fa fa-trash me-1"></i>DELETED</span>`;
                } else {
                    location.reload();
                }
            }
        }

        // Handle: Sync, Replace Core, DB Clean
        async function apiCall(btn, action, extraData = {}) {
            if (!confirm('Jalankan operasi sistem: ' + action + '?')) return;

            const res = await sendRequest(action, extraData, btn);
            alert((res.status === 'success' ? '✅ ' : '❌ ') + res.msg);
            if (res.status === 'success') {
                location.reload();
            }
        }

        // === UI Functions ===

        // Filter by severity
        function filterResults() {
            const filter = document.getElementById('filterSeverity').value;
            const rows = document.querySelectorAll('#scanResultsTable tbody tr');
            rows.forEach(row => {
                if (!filter || row.dataset.severity === filter) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }

        // Sort ascending/descending by score
        let sortAsc = false;
        function sortByScore() {
            const tbody = document.querySelector('#scanResultsTable tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            rows.sort((a, b) => {
                const scoreA = parseFloat(a.dataset.score) || 0;
                const scoreB = parseFloat(b.dataset.score) || 0;
                return sortAsc ? scoreA - scoreB : scoreB - scoreA;
            });
            rows.forEach(row => tbody.appendChild(row));
            sortAsc = !sortAsc;
        }

        // Toggle select all checkboxes
        function toggleSelectAll() {
            const checked = document.getElementById('selectAll').checked;
            document.querySelectorAll('.row-select').forEach(cb => cb.checked = checked);
            updateSelectedCount();
        }

        // Update selected count and button states
        function updateSelectedCount() {
            const count = document.querySelectorAll('.row-select:checked').length;
            document.getElementById('selectedCount').textContent = count;
            document.getElementById('bulkDeleteBtn').disabled = count === 0;
        }

        // Bulk delete selected files
        async function bulkDeleteSelected() {
            const selected = document.querySelectorAll('.row-select:checked');
            if (selected.length === 0) return;
            const btn = document.getElementById('bulkDeleteBtn');

            if (!confirm('Hapus ' + selected.length + ' temuan terpilih?')) return;

            const paths = [];
            selected.forEach(cb => {
                const row = cb.closest('tr');
                paths.push(b64DecodeUnicode(row.dataset.path));
            });

            const res = await sendRequest('bulk_delete', { paths: JSON.stringify(paths) }, btn);
            if (res.msg) alert(res.msg);

            // Cache Synchronization
            const cached = loadScanResults(STORAGE_KEY_FILES);
            if (cached && cached.data && cached.data.results) {
                cached.data.results = cached.data.results.filter(r => !paths.includes(r.path));
                cached.data.summary.total = cached.data.results.length;
                cached.data.summary.critical = cached.data.results.filter(r => r.severity === 'CRITICAL').length;
                cached.data.summary.suspicious = cached.data.results.filter(r => r.severity === 'SUSPICIOUS').length;
                saveScanResults(STORAGE_KEY_FILES, cached.data);
            }

            location.reload();
        }

        // v9.0: Comprehensive PDF Export from Cache
        async function exportResults() {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            const now = new Date();
            const timestamp = now.toLocaleString('id-ID');

            // Load Data
            const fileData = loadScanResults(STORAGE_KEY_FILES);
            const dbData = loadScanResults(STORAGE_KEY_DB);

            if (!fileData || !dbData) {
                alert("Data scan tidak lengkap. Pastikan File Scan dan Database Scan sudah dijalankan.");
                return;
            }

            // --- 🛡️ PDF DESIGN ---

            // 1. Header
            doc.setFillColor(38, 50, 56); // Deep blue-gray
            doc.rect(0, 0, 210, 40, 'F');

            doc.setTextColor(255, 140, 0); // Accent orange
            doc.setFontSize(24);
            doc.setFont("helvetica", "bold");
            doc.text("RADAR SECURITY REPORT", 15, 20);

            doc.setTextColor(200, 200, 200);
            doc.setFontSize(10);
            doc.setFont("helvetica", "normal");
            doc.text("v4.5 Enterprise Edition | Automated Security Analysis", 15, 28);

            doc.setTextColor(255, 255, 255);
            doc.text(`Generated: ${timestamp}`, 140, 20);
            doc.text(`Root: ${fileData.data?.root || 'N/A'}`, 140, 28);

            // 2. Executive Summary
            doc.setTextColor(0, 0, 0);
            doc.setFontSize(16);
            doc.text("Executive Summary", 15, 55);

            const summaryData = [
                ["Category", "Total Found", "Critical", "Suspicious"],
                ["File Infections", fileData.data?.summary?.total || 0, fileData.data?.summary?.critical || 0, fileData.data?.summary?.suspicious || 0],
                ["Database Issues", dbData.data?.summary?.total_issues || 0, dbData.data?.summary?.spam_posts || 0, dbData.data?.summary?.suspicious_users || 0]
            ];

            doc.autoTable({
                startY: 60,
                head: [summaryData[0]],
                body: summaryData.slice(1),
                theme: 'striped',
                headStyles: { fillColor: [255, 140, 0] }
            });

            // 3. File Scan Details
            let finalY = doc.lastAutoTable.finalY + 15;
            doc.setFontSize(16);
            doc.text("File Scan Details", 15, finalY);

            const fileRows = (fileData.data?.results || []).map(r => [
                r.path.split('/').pop(),
                r.severity,
                r.score,
                r.reason
            ]);

            doc.autoTable({
                startY: finalY + 5,
                head: [['Filename', 'Severity', 'Score', 'Primary Reason']],
                body: fileRows,
                columnStyles: { 3: { cellWidth: 80 } },
                theme: 'grid',
                headStyles: { fillColor: [52, 73, 94] }
            });

            // 4. Database Scan Details
            finalY = doc.lastAutoTable.finalY + 15;
            if (finalY > 250) { doc.addPage(); finalY = 20; }
            doc.setFontSize(16);
            doc.text("Database Scan Details", 15, finalY);

            const dbRows = [];
            (dbData.data?.posts || []).forEach(p => dbRows.push(['Post', p.id, 'Spam Content', p.severity]));
            (dbData.data?.users || []).forEach(u => dbRows.push(['User', u.id, u.reason, u.severity]));
            (dbData.data?.options || []).forEach(o => dbRows.push(['Option', o.id, o.reason, o.severity]));

            doc.autoTable({
                startY: finalY + 5,
                head: [['Type', 'ID', 'Issue Description', 'Severity']],
                body: dbRows,
                theme: 'grid',
                headStyles: { fillColor: [52, 73, 94] }
            });

            // 5. Footer
            const pageCount = doc.internal.getNumberOfPages();
            for (let i = 1; i <= pageCount; i++) {
                doc.setPage(i);
                doc.setFontSize(10);
                doc.setTextColor(150);
                doc.text(`RadarKit - Confidential Security Report | Page ${i} of ${pageCount}`, 105, 290, null, null, "center");
            }

            // Save PDF
            doc.save(`Radar_Security_Report_${now.toISOString().split('T')[0]}.pdf`);
        }
        // === Database Scan Functions ===

        async function startDBScan() {
            const startTime = Date.now();
            setProgress(0); // Reset progress

            const btn = document.getElementById('btnDBScan');
            const placeholder = document.getElementById('dbScanPlaceholder');
            const container = document.getElementById('dbScanResultsContainer');
            const overlay = document.getElementById('scan-overlay');
            const title = document.getElementById('scan-title');
            const desc = document.getElementById('scan-desc');

            if (title) title.innerText = 'Database Scanning...';
            if (desc) desc.innerText = 'Analyzing post spam and weak accounts. Please wait.';

            if (overlay) overlay.style.display = 'flex';
            if (btn) btn.disabled = true;

            // Progress Simulation (0 to 90%)
            const progInt = setInterval(() => {
                const elapsed = Date.now() - startTime;
                const progress = Math.min(90, (elapsed / 2000) * 90);
                setProgress(progress);
            }, 100);

            try {
                // Ambil site_id dari dropdown (null jika single site)
                const siteSelector = document.getElementById('dbSiteSelectorDropdown');
                const siteId = siteSelector ? siteSelector.value : null;
                const postData = siteId ? { site_id: siteId } : {};

                const res = await sendRequest('db_scan', postData);

                // Snap to 100% once done
                clearInterval(progInt);
                setProgress(100);

                if (res.status === 'success' && res.data) {
                    // Save to sessionStorage
                    saveScanResults(STORAGE_KEY_DB, res.data);

                    // v9.0: Update button state
                    updateExportButtonState();

                    if (placeholder) placeholder.style.display = 'none';
                    if (container) container.style.display = 'block';

                    // v4.5.2: Use unified restorer for consistency (Fires same badge/render logic)
                    restoreDBScanResults(res.data);
                } else {
                    alert('Database scan error: ' + (res.msg || 'Unknown error'));
                }
            } catch (e) {
                clearInterval(progInt);
                alert('Error: ' + e.message);
            } finally {
                // Professional Duration (Min 2000ms)
                const elapsed = Date.now() - startTime;
                if (elapsed < 2000) await sleep(2000 - elapsed);

                // Extra brief wait to let them see 100%
                await sleep(300);

                if (overlay) overlay.style.display = 'none';
                if (btn) btn.disabled = false;
                if (btn) btn.innerHTML = '<i class="fa fa-refresh me-1"></i>Re-Scan';
            }
        }

        function renderDBPosts(posts, page = 1) {
            const container = document.getElementById('dbPostsResults');
            if (!container) return; // Safety check
            if (!Array.isArray(posts) || posts.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-5 bg-black bg-opacity-10 rounded">
                        <i class="fa fa-check-circle fa-4x text-success mb-3" style="opacity:0.6"></i>
                        <p class="h5 text-success mb-2">Database Bersih!</p>
                        <p class="text-white-50 small mb-0">Tidak ada post spam atau konten mencurigakan terdeteksi.</p>
                    </div>`;
                return;
            }

            const itemsPerPage = 10;
            const start = (page - 1) * itemsPerPage;
            const pagedPosts = posts.slice(start, start + itemsPerPage);

            let html = '<div class="table-responsive"><table class="table table-sm table-dark mb-0 align-middle small">';
            html += '<thead><tr><th class="ps-3" style="width:45px;"><input type="checkbox" id="selectAllPosts" class="form-check-input" onchange="toggleDBSelectAll(\'posts\')"></th><th style="width:60px;">ID</th><th>JUDUL POST</th><th style="width:100px;">TIPE</th><th>KATA KUNCI</th><th style="width:120px;">TINGKAT</th><th style="width:80px;" class="text-end pe-3">AKSI</th></tr></thead><tbody>';

            pagedPosts.forEach(p => {
                if (p.error) {
                    html += `<tr><td colspan="6" class="text-danger ps-3">${p.error}</td></tr>`;
                    return;
                }
                const sevClass = p.severity === 'CRITICAL' ? 'bg-danger' : 'bg-warning text-dark';
                html += `<tr>
                    <td class="ps-3"><input type="checkbox" class="form-check-input db-row-select" data-type="posts" data-id="${p.id}" onchange="updateDBSelectedCount()"></td>
                    <td>${p.id}</td>
                    <td class="small">${escapeHtml(p.title || 'N/A')}</td>
                    <td><span class="badge bg-secondary">${p.type}</span></td>
                    <td class="small">${(p.keywords || []).map(k => `<span class="factor f-danger">${k}</span>`).join('')}</td>
                    <td><span class="badge ${sevClass}">${p.severity}</span></td>
                    <td class="text-end pe-3">
                        <button class="btn btn-sm btn-outline-danger" onclick="dbBulkDeleteItem('posts', '${p.id}', this)" title="Hapus">
                            <i class="fa fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            });

            html += '</tbody></table></div>';
            html += '<div id="dbPostsPagination" class="pagination-container"></div>';
            container.innerHTML = html;

            renderPagination('dbPostsPagination', posts.length, itemsPerPage, page, 'changeDBPostsPage');
        }

        function changeDBPostsPage(page) {
            const cached = loadScanResults(STORAGE_KEY_DB);
            if (cached && cached.data) renderDBPosts(cached.data.posts, page);
        }

        function renderDBOptions(options, page = 1) {
            const container = document.getElementById('dbOptionsResults');
            if (!container) return;
            if (!Array.isArray(options) || options.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-5 bg-black bg-opacity-10 rounded">
                        <i class="fa fa-check-circle fa-4x text-success mb-3" style="opacity:0.6"></i>
                        <p class="h5 text-success mb-2">Opsi Database Aman!</p>
                        <p class="text-white-50 small mb-0">Tidak ada pengaturan (options) yang mencurigakan terdeteksi.</p>
                    </div>`;
                return;
            }

            const itemsPerPage = 10;
            const start = (page - 1) * itemsPerPage;
            const pagedOptions = options.slice(start, start + itemsPerPage);

            let html = '<div class="table-responsive"><table class="table table-sm table-dark mb-0 align-middle small">';
            html += '<thead><tr><th class="ps-3" style="width: 45px;"><input type="checkbox" id="selectAllOptions" class="form-check-input" onchange="toggleDBSelectAll(\'options\')"></th><th style="width:60px;">ID</th><th>NAMA OPSI</th><th style="width:100px;">UKURAN</th><th>ALASAN</th><th style="width:120px;">TINGKAT</th><th style="width:80px;" class="text-end pe-3">AKSI</th></tr></thead><tbody>';

            pagedOptions.forEach(o => {
                if (o.error) {
                    html += `<tr><td colspan="6" class="text-danger ps-3">${o.error}</td></tr>`;
                    return;
                }
                const sevClass = o.severity === 'CRITICAL' ? 'bg-danger' : 'bg-warning text-dark';
                html += `<tr>
                    <td class="ps-3"><input type="checkbox" class="form-check-input db-row-select" data-type="options" data-id="${o.id}" onchange="updateDBSelectedCount()"></td>
                    <td>${o.id}</td>
                    <td class="small font-monospace">${escapeHtml(o.name || 'N/A')}</td>
                    <td>${o.size}</td>
                    <td class="small">${escapeHtml(o.reason || '')}</td>
                    <td><span class="badge ${sevClass}">${o.severity}</span></td>
                    <td class="text-end pe-3">
                        <button class="btn btn-sm btn-outline-danger" onclick="dbBulkDeleteItem('options', '${o.id}', this)" title="Hapus">
                            <i class="fa fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            });

            html += '</tbody></table></div>';
            html += '<div id="dbOptionsPagination" class="pagination-container"></div>';
            container.innerHTML = html;

            renderPagination('dbOptionsPagination', options.length, itemsPerPage, page, 'changeDBOptionsPage');
        }

        function changeDBOptionsPage(page) {
            const cached = loadScanResults(STORAGE_KEY_DB);
            if (cached && cached.data) renderDBOptions(cached.data.options, page);
        }

        function renderDBUsers(users, page = 1) {
            const container = document.getElementById('dbUsersResults');
            if (!container) return;
            if (!Array.isArray(users) || users.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-5 bg-black bg-opacity-10 rounded">
                        <i class="fa fa-check-circle fa-4x text-success mb-3" style="opacity:0.6"></i>
                        <p class="h5 text-success mb-2">Pengguna Database Aman!</p>
                        <p class="text-white-50 small mb-0">Tidak ada akun pengguna yang mencurigakan terdeteksi.</p>
                    </div>`;
                return;
            }

            const itemsPerPage = 10;
            const start = (page - 1) * itemsPerPage;
            const pagedUsers = users.slice(start, start + itemsPerPage);

            let html = '<div class="table-responsive"><table class="table table-sm table-dark mb-0 align-middle small">';
            html += '<thead><tr><th class="ps-3" style="width: 45px;"><input type="checkbox" id="selectAllUsers" class="form-check-input" onchange="toggleDBSelectAll(\'users\')"></th><th style="width:60px;">ID</th><th>USERNAME</th><th>EMAIL</th><th style="width:140px;">TERDAFTAR</th><th>ALASAN</th><th style="width:120px;">TINGKAT</th><th style="width:80px;" class="text-end pe-3">AKSI</th></tr></thead><tbody>';

            pagedUsers.forEach(u => {
                if (u.error) {
                    html += `<tr><td colspan="7" class="text-danger ps-3">${u.error}</td></tr>`;
                    return;
                }
                let sevClass = 'bg-secondary';
                if (u.severity === 'CRITICAL') sevClass = 'bg-danger';
                else if (u.severity === 'WARNING') sevClass = 'bg-warning text-dark';
                else if (u.severity === 'REVIEW') sevClass = 'bg-info text-dark';

                html += `<tr>
                    <td class="ps-3"><input type="checkbox" class="form-check-input db-row-select" data-type="users" data-id="${u.id}" onchange="updateDBSelectedCount()"></td>
                    <td>${u.id || 'N/A'}</td>
                    <td class="small">${escapeHtml(u.username || 'N/A')}</td>
                    <td class="small">${escapeHtml(u.email || 'N/A')}</td>
                    <td class="small">${u.registered || 'N/A'}</td>
                    <td class="small">${escapeHtml(u.reason || '')}</td>
                    <td><span class="badge ${sevClass}">${u.severity}</span></td>
                    <td class="text-end pe-3">
                        <button class="btn btn-sm btn-outline-danger" onclick="dbBulkDeleteItem('users', '${u.id}', this)" title="Hapus">
                            <i class="fa fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            });

            html += '</tbody></table></div>';
            html += '<div id="dbUsersPagination" class="pagination-container"></div>';
            container.innerHTML = html;

            renderPagination('dbUsersPagination', users.length, itemsPerPage, page, 'changeDBUsersPage');
        }

        function changeDBUsersPage(page) {
            const cached = loadScanResults(STORAGE_KEY_DB);
            if (cached && cached.data) renderDBUsers(cached.data.users, page);
        }

        function renderDBRedirects(redirects, page = 1) {
            const container = document.getElementById('dbRedirectsResults');
            if (!container) return;
            if (!Array.isArray(redirects) || redirects.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-5 bg-black bg-opacity-10 rounded">
                        <i class="fa fa-check-circle fa-4x text-success mb-3" style="opacity:0.6"></i>
                        <p class="h5 text-success mb-2">Redirect Injection Bersih!</p>
                        <p class="text-white-50 small mb-0">Tidak ditemukan kode redirect berbahaya di tabel wp_posts.</p>
                    </div>`;
                return;
            }

            const itemsPerPage = 10;
            const start = (page - 1) * itemsPerPage;
            const pagedRedirects = redirects.slice(start, start + itemsPerPage);

            let html = '<div class="table-responsive"><table class="table table-sm table-dark mb-0 align-middle small">';
            html += '<thead><tr><th class="ps-3" style="width: 45px;"><input type="checkbox" id="selectAllRedirects" class="form-check-input" onchange="toggleDBSelectAll(\'redirects\')"></th><th style="width:60px;">ID</th><th>JUDUL POST</th><th style="width:100px;">TIPE</th><th>ALASAN</th><th style="width:120px;">TINGKAT</th><th style="width:80px;" class="text-end pe-3">AKSI</th></tr></thead><tbody>';

            pagedRedirects.forEach(r => {
                html += `<tr>
                    <td class="ps-3"><input type="checkbox" class="form-check-input db-row-select" data-type="redirects" data-id="${r.id}" onchange="updateDBSelectedCount()"></td>
                    <td>${r.id}</td>
                    <td class="small">${escapeHtml(r.title || 'N/A')}</td>
                    <td><span class="badge bg-secondary">${r.type}</span></td>
                    <td class="small text-danger">${escapeHtml(r.reason || '')}</td>
                    <td><span class="badge bg-danger">${r.severity}</span></td>
                    <td class="text-end pe-3">
                        <button class="btn btn-sm btn-outline-danger" onclick="dbBulkDeleteItem('redirects', '${r.id}', this)" title="Hapus">
                            <i class="fa fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            });

            html += '</tbody></table></div>';
            html += '<div id="dbRedirectPagination" class="pagination-container"></div>';
            container.innerHTML = html;

            renderPagination('dbRedirectPagination', redirects.length, itemsPerPage, page, 'changeDBRedirectsPage');
        }

        /**
         * DB Bulk Delete Implementation
         */
        function toggleDBSelectAll(type) {
            const master = document.getElementById('selectAll' + type.charAt(0).toUpperCase() + type.slice(1));
            const checkboxes = document.querySelectorAll(`.db-row-select[data-type="${type}"]`);
            checkboxes.forEach(cb => cb.checked = master.checked);
            updateDBSelectedCount();
        }

        function updateDBSelectedCount() {
            const count = document.querySelectorAll('.db-row-select:checked').length;
            const btn = document.getElementById('btnDBBulkDelete');
            const countDisplay = document.getElementById('dbSelectedCount');

            if (countDisplay) countDisplay.textContent = count;
            if (btn) btn.disabled = (count === 0);
        }

        async function dbBulkDelete() {
            const selected = document.querySelectorAll('.db-row-select:checked');
            if (selected.length === 0) return;
            const btn = document.getElementById('btnDBBulkDelete');

            if (!confirm('Hapus ' + selected.length + ' temuan terpilih?')) return;

            const tasks = { posts: [], options: [], users: [], redirects: [] };
            selected.forEach(cb => {
                tasks[cb.dataset.type].push(cb.dataset.id);
            });

            try {
                for (const type in tasks) {
                    if (tasks[type].length > 0) {
                        // v4.7.5: Filter out dummy/warning IDs
                        // v5.0: Deduplicate IDs
                        let validIds = tasks[type].filter(id => id && id != "0");
                        validIds = [...new Set(validIds)];

                        if (validIds.length === 0) continue;

                        const action = `db_delete_${type}`;
                        const siteSelector = document.getElementById('dbSiteSelectorDropdown');
                        const siteId = siteSelector ? siteSelector.value : null;

                        const res = await sendRequest(action, {
                            ids: JSON.stringify(validIds),
                            ...(siteId && { site_id: siteId })
                        }, btn);

                        // Sync cache only for successful categories
                        if (res.status === 'success') {
                            const partialTask = { posts: [], options: [], users: [], redirects: [] };
                            partialTask[type] = validIds;
                            syncDBCache(partialTask);
                        }
                    }
                }

                alert('Berhasil memproses penghapusan data terpilih!');
                await sleep(500); // v4.8.0: Delay to ensure cache write
                location.reload();
            } catch (e) {
                alert('Kesalahan: ' + e.message);
            }
        }

        // v4.7.2: Individual delete for DB items
        async function dbBulkDeleteItem(type, id, btn) {
            if (!confirm('Hapus temuan ini?')) return;

            const tasks = { posts: [], options: [], users: [], redirects: [] };
            tasks[type].push(id);

            try {
                const action = `db_delete_${type}`;
                const siteSelector = document.getElementById('dbSiteSelectorDropdown');
                const siteId = siteSelector ? siteSelector.value : null;

                const res = await sendRequest(action, {
                    ids: JSON.stringify([id]),
                    ...(siteId && { site_id: siteId })
                }, btn);
                if (res.status === 'error') throw new Error(res.msg);

                // Sinkronisasi Cache
                syncDBCache(tasks);

                alert('Berhasil menghapus item.');
                await sleep(500); // v4.8.0: Delay to ensure cache write
                location.reload();
            } catch (e) {
                alert('Kesalahan: ' + e.message);
            }
        }

        // v4.7.2: Shared Cache Sync Logic for DB
        function syncDBCache(tasks) {
            try {
                // v5.0: Deep Copy Cache to prevent reference leaks
                const rawCached = loadScanResults(STORAGE_KEY_DB);
                if (!rawCached || !rawCached.data) return;

                const cachedData = JSON.parse(JSON.stringify(rawCached.data));

                // v4.8.0: Strict Type Filtering (String Comparison) to prevent greedy matches
                // Ensure we only remove IDs that EXACTLY match the deletion task
                const removePosts = (tasks.posts || []).map(String);
                const removeOptions = (tasks.options || []).map(String);
                const removeUsers = (tasks.users || []).map(String);
                const removeRedirects = (tasks.redirects || []).map(String);

                if (removePosts.length) cachedData.posts = (cachedData.posts || []).filter(p => !p || p.id === 0 || !removePosts.includes(String(p.id)));
                if (removeOptions.length) cachedData.options = (cachedData.options || []).filter(o => !o || o.id === 0 || !removeOptions.includes(String(o.id)));
                if (removeUsers.length) cachedData.users = (cachedData.users || []).filter(u => !u || u.id === 0 || !removeUsers.includes(String(u.id)));
                if (removeRedirects.length) cachedData.redirects = (cachedData.redirects || []).filter(r => !r || r.id === 0 || !removeRedirects.includes(String(r.id)));

                saveScanResults(STORAGE_KEY_DB, cachedData);
            } catch (e) {
                console.error("Radar Error: Failed to sync DB cache", e);
            }
        }

        function changeDBRedirectsPage(page) {
            const cached = loadScanResults(STORAGE_KEY_DB);
            if (cached && cached.data) renderDBRedirects(cached.data.redirects, page);
        }

        // v4.5: State restoration is handled by the main DOMContentLoaded listener
        // defined earlier in the script (around line 2122)

        // v4.5: Update progress bar percentage
        function setProgress(percent) {
            const fill = document.querySelector('.loader-fill');
            if (fill) fill.style.width = percent + '%';
        }

        // v4.5: Helpers
        const sleep = ms => new Promise(res => setTimeout(res, ms));

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.innerText = text;
            return div.innerHTML;
        }

        // v4.5: Unicode-safe Base64 Encoding
        function b64EncodeUnicode(str) {
            return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function (match, p1) {
                return String.fromCharCode('0x' + p1);
            }));
        }

        // Unicode-safe Base64 Decoding
        function b64DecodeUnicode(str) {
            return decodeURIComponent(atob(str).split('').map(function (c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
        }
    </script>
    <!-- Bootstrap 5 JS Bundle (Required for Tabs) -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>