<?php
/**
 * 🛡️ Radar Database Scanner v4.0
 * Scanner terpisah untuk database WordPress
 * 
 * Fungsi:
 * - Scan wp_posts untuk konten spam
 * - Scan wp_options untuk entry mencurigakan
 * - Scan wp_users untuk admin asing
 * 
 * @package RadarKit
 * @version 4.0
 * @updated 2026-02-07
 */

// Include signature database
require_once __DIR__ . '/radar_signatures.php';

class RadarDBScanner
{
    private $pdo;
    private $prefix;
    private $results = [];
    private $signatures;

    /**
     * Constructor
     * 
     * @param PDO $pdo Database connection
     * @param string $prefix Table prefix (default: wp_)
     * @param array|null $signatures Signature database (dari SignatureProvider)
     */
    public function __construct($pdo, $prefix = 'wp_', $signatures = null)
    {
        $this->pdo = $pdo;
        $this->prefix = $prefix;
        $this->signatures = $signatures ?? SignatureProvider::getSignatures();
    }

    /**
     * Jalankan semua scan
     * 
     * @param int $postLimit Limit untuk scan posts
     * @return array Hasil scan
     */
    public function runFullScan($postLimit = 500)
    {
        $this->results = [
            'scan_time' => date('Y-m-d H:i:s'),
            'posts' => $this->scanPosts($postLimit),
            'options' => $this->scanOptions(),
            'users' => $this->scanUsers(),
            'redirects' => $this->scanRedirectInjection(),
            'summary' => []
        ];

        // Generate summary
        // v4.5.2: Only count actual users (ID > 0), exclude ID 0 (Warnings)
        $actualUsers = array_filter($this->results['users'], fn($u) => isset($u['id']) && $u['id'] > 0);

        $this->results['summary'] = [
            'spam_posts' => count($this->results['posts']),
            'suspicious_options' => count($this->results['options']),
            'suspicious_users' => count($actualUsers),
            'redirect_injections' => count($this->results['redirects']),
            'total_issues' => count($this->results['posts']) +
                count($this->results['options']) +
                count($actualUsers) +
                count($this->results['redirects'])
        ];

        return $this->results;
    }

    /**
     * Scan wp_posts untuk konten spam
     * 
     * @param int $limit Maksimal post yang di-scan
     * @return array Post yang terinfeksi
     */
    public function scanPosts($limit = 500)
    {
        $infected = [];
        $table = $this->prefix . 'posts';

        // Gabungkan semua keywords
        $keywords = array_merge(
            $this->signatures['gamblingKeywords'] ?? [],
            $this->signatures['pharmaKeywords'] ?? [],
            $this->signatures['japaneseSpamKeywords'] ?? [],
            $this->signatures['chineseSpamKeywords'] ?? []
        );

        try {
            // Query untuk mendapatkan posts terbaru
            // Note: LIMIT harus integer, bukan prepared statement parameter
            $limit = intval($limit);
            $sql = "SELECT ID, post_title, post_type, post_status, post_date, 
                           SUBSTRING(post_content, 1, 500) as content_preview
                    FROM {$table} 
                    WHERE post_status IN ('publish', 'draft', 'private')
                    ORDER BY post_date DESC 
                    LIMIT {$limit}";

            $stmt = $this->pdo->query($sql);
            $posts = $stmt->fetchAll();

            foreach ($posts as $post) {
                $matchedKeywords = [];
                $searchText = strtolower($post['post_title'] . ' ' . $post['content_preview']);

                foreach ($keywords as $kw) {
                    if (stripos($searchText, $kw) !== false) {
                        $matchedKeywords[] = $kw;
                    }
                }

                // Jika ada 2+ keyword match, tandai sebagai spam
                // Khusus untuk Karakter Jepang/China, 1 match saja sudah cukup mencurigakan
                $hasForeign = false;
                foreach ($matchedKeywords as $mk) {
                    if (in_array($mk, $this->signatures['japaneseSpamKeywords'] ?? []) || in_array($mk, $this->signatures['chineseSpamKeywords'] ?? [])) {
                        $hasForeign = true;
                        break;
                    }
                }

                if (count($matchedKeywords) >= 2 || $hasForeign) {
                    $infected[] = [
                        'id' => $post['ID'],
                        'title' => mb_substr($post['post_title'], 0, 100),
                        'type' => $post['post_type'],
                        'status' => $post['post_status'],
                        'date' => $post['post_date'],
                        'keywords' => array_slice($matchedKeywords, 0, 5), // Max 5 keywords
                        'severity' => (count($matchedKeywords) >= 5 || $hasForeign) ? 'CRITICAL' : 'SUSPICIOUS'
                    ];
                }
            }
        } catch (Exception $e) {
            $infected[] = ['error' => $e->getMessage()];
        }

        return $infected;
    }

    /**
     * Scan wp_options untuk entry mencurigakan
     * 
     * @return array Options yang mencurigakan
     */
    public function scanOptions()
    {
        $suspicious = [];
        $table = $this->prefix . 'options';

        // Patterns untuk option name
        $suspiciousNames = [
            'wp_vcd',
            'base64_code',
            'backdoor',
            'shell',
            'malware',
            'hack',
            '_transient_feed_',  // Transient yang expired sering dipakai
        ];

        // Patterns untuk option value
        $suspiciousValues = [
            'eval(',
            'base64_decode(',
            'gzinflate(',
            'shell_exec(',
            'passthru(',
        ];

        try {
            // Scan berdasarkan nama option
            $namePatterns = array_map(function ($p) {
                return "%{$p}%";
            }, $suspiciousNames);
            $placeholders = rtrim(str_repeat('option_name LIKE ? OR ', count($namePatterns)), ' OR ');

            $sql = "SELECT option_id, option_name, 
                           SUBSTRING(option_value, 1, 200) as value_preview,
                           LENGTH(option_value) as value_length
                    FROM {$table} 
                    WHERE {$placeholders}
                    LIMIT 100";

            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($namePatterns);
            $options = $stmt->fetchAll();

            foreach ($options as $opt) {
                $suspicious[] = [
                    'id' => $opt['option_id'],
                    'name' => $opt['option_name'],
                    'value_preview' => mb_substr($opt['value_preview'], 0, 100),
                    'size' => $this->formatBytes($opt['value_length']),
                    'reason' => 'Suspicious option name',
                    'severity' => 'SUSPICIOUS'
                ];
            }

            // Scan berdasarkan value (untuk encoded content)
            // v4.5.1: Remove \x check to reduce false positives in serialized data
            $sql = "SELECT option_id, option_name, 
                           SUBSTRING(option_value, 1, 200) as value_preview,
                           LENGTH(option_value) as value_length
                    FROM {$table} 
                    WHERE option_value LIKE '%eval(%' 
                       OR option_value LIKE '%base64_decode(%'
                       OR option_value LIKE '%gzinflate(%'
                    LIMIT 50";

            $stmt = $this->pdo->query($sql);
            $options = $stmt->fetchAll();

            // Whitelist opsi core yang sering mengandung data serialisasi aman
            $whitelistOptions = [
                'cron',
                'rewrite_rules',
                'wp_user_roles',
                'mailserver_url',
                'mailserver_login',
                'admin_email',
                'permalink_structure'
            ];

            foreach ($options as $opt) {
                // Skip if in whitelist
                if (in_array($opt['option_name'], $whitelistOptions))
                    continue;

                // Cek apakah sudah ada di list
                $exists = array_filter($suspicious, fn($s) => $s['id'] === $opt['option_id']);
                if (empty($exists)) {
                    $suspicious[] = [
                        'id' => $opt['option_id'],
                        'name' => $opt['option_name'],
                        'value_preview' => mb_substr($opt['value_preview'], 0, 100),
                        'size' => $this->formatBytes($opt['value_length']),
                        'reason' => 'Suspicious code pattern in value',
                        'severity' => 'CRITICAL'
                    ];
                }
            }

            // Scan untuk option dengan value sangat besar (potential encoded payload)
            $sql = "SELECT option_id, option_name, 
                           LENGTH(option_value) as value_length
                    FROM {$table} 
                    WHERE LENGTH(option_value) > 100000
                      AND option_name NOT LIKE '%_transient_%'
                      AND option_name NOT IN ('theme_mods_*', 'sidebars_widgets')
                    LIMIT 20";

            $stmt = $this->pdo->query($sql);
            $largeOptions = $stmt->fetchAll();

            foreach ($largeOptions as $opt) {
                $exists = array_filter($suspicious, fn($s) => $s['id'] === $opt['option_id']);
                if (empty($exists)) {
                    $suspicious[] = [
                        'id' => $opt['option_id'],
                        'name' => $opt['option_name'],
                        'value_preview' => '[Large Value]',
                        'size' => $this->formatBytes($opt['value_length']),
                        'reason' => 'Unusually large option value',
                        'severity' => 'SUSPICIOUS'
                    ];
                }
            }

        } catch (Exception $e) {
            $suspicious[] = ['error' => $e->getMessage()];
        }

        return $suspicious;
    }

    /**
     * Scan wp_users untuk admin asing
     * 
     * @return array User yang mencurigakan
     */
    public function scanUsers()
    {
        $suspicious = [];
        // Di multisite, wp_users dan wp_usermeta selalu global (tanpa blog_id)
        // Ekstrak base prefix (hapus angka blog_id jika ada)
        $basePrefix = preg_replace('/\d+_$/', '', $this->prefix);
        $usersTable = $basePrefix . 'users';
        $metaTable = $basePrefix . 'usermeta';

        try {
            // Cari administrator yang dibuat dalam 30 hari terakhir
            $sql = "SELECT u.ID, u.user_login, u.user_email, u.user_registered,
                           um.meta_value as capabilities
                    FROM {$usersTable} u
                    JOIN {$metaTable} um ON u.ID = um.user_id
                    WHERE um.meta_key = '{$this->prefix}capabilities'
                      AND um.meta_value LIKE '%administrator%'
                      AND u.user_registered > DATE_SUB(NOW(), INTERVAL 30 DAY)
                    ORDER BY u.user_registered DESC";

            $stmt = $this->pdo->query($sql);
            $users = $stmt->fetchAll();

            foreach ($users as $user) {
                // Cek email pattern mencurigakan
                $suspiciousEmail = false;
                $email = strtolower($user['user_email']);

                $suspiciousPatterns = [
                    '@tempmail',
                    '@guerrilla',
                    '@mailinator',
                    '@10minute',
                    '@throwaway',
                    '@yopmail',
                    '@sharklasers',
                    '@getnada',
                    'admin@',
                    'test@',
                    '123@',
                ];

                foreach ($suspiciousPatterns as $pattern) {
                    if (strpos($email, $pattern) !== false) {
                        $suspiciousEmail = true;
                        break;
                    }
                }

                // Cek username pattern
                $suspiciousUsername = preg_match('/^(admin|user|test|temp|hack)[0-9]+$/i', $user['user_login']);

                if ($suspiciousEmail || $suspiciousUsername) {
                    $suspicious[] = [
                        'id' => $user['ID'],
                        'username' => $user['user_login'],
                        'email' => $user['user_email'],
                        'registered' => $user['user_registered'],
                        'reason' => $suspiciousEmail ? 'Suspicious email pattern' : 'Suspicious username pattern',
                        'severity' => 'CRITICAL'
                    ];
                } else {
                    // Tetap report admin baru sebagai perlu review
                    $suspicious[] = [
                        'id' => $user['ID'],
                        'username' => $user['user_login'],
                        'email' => $user['user_email'],
                        'registered' => $user['user_registered'],
                        'reason' => 'New administrator (created within 30 days)',
                        'severity' => 'REVIEW'
                    ];
                }
            }

            // Cari user dengan privilege escalation
            $sql = "SELECT u.ID, u.user_login, u.user_email
                    FROM {$usersTable} u
                    JOIN {$metaTable} um ON u.ID = um.user_id
                    WHERE um.meta_key = '{$this->prefix}capabilities'
                      AND um.meta_value LIKE '%administrator%'
                    ORDER BY u.ID";

            $stmt = $this->pdo->query($sql);
            $allAdmins = $stmt->fetchAll();

            // Jika ada lebih dari 3 admin, mungkin ada privilege escalation
            if (count($allAdmins) > 3) {
                $suspicious[] = [
                    'id' => 0,
                    'username' => 'N/A',
                    'email' => 'N/A',
                    'registered' => 'N/A',
                    'reason' => 'Warning: ' . count($allAdmins) . ' administrator accounts exist. Please review.',
                    'severity' => 'WARNING'
                ];
            }

        } catch (Exception $e) {
            $suspicious[] = ['error' => $e->getMessage()];
        }

        return $suspicious;
    }

    /**
     * Scan untuk redirect injection di wp_posts
     * 
     * @return array Posts dengan redirect code
     */
    public function scanRedirectInjection()
    {
        $infected = [];
        $table = $this->prefix . 'posts';

        $patterns = [
            '%<script%location%</script>%',
            '%<script%window.location%</script>%',
            '%<meta%http-equiv%refresh%',
            '%header(%Location%',
            '%.htaccess%Redirect%',
        ];

        try {
            $placeholders = rtrim(str_repeat('post_content LIKE ? OR ', count($patterns)), ' OR ');

            $sql = "SELECT ID, post_title, post_type, post_date
                    FROM {$table} 
                    WHERE {$placeholders}
                    LIMIT 100";

            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($patterns);
            $posts = $stmt->fetchAll();

            foreach ($posts as $post) {
                $infected[] = [
                    'id' => $post['ID'],
                    'title' => mb_substr($post['post_title'], 0, 100),
                    'type' => $post['post_type'],
                    'date' => $post['post_date'],
                    'reason' => 'Redirect code injection',
                    'severity' => 'CRITICAL'
                ];
            }
        } catch (Exception $e) {
            $infected[] = ['error' => $e->getMessage()];
        }

        return $infected;
    }

    /**
     * Quick delete spam posts by IDs
     * 
     * @param array $ids Array of post IDs to delete
     * @return array Result
     */
    public function deleteSpamPosts($ids)
    {
        if (empty($ids) || !is_array($ids)) {
            return ['status' => 'error', 'msg' => 'No IDs provided'];
        }

        // Sanitize IDs
        $ids = array_filter(array_map('intval', $ids));
        $table = $this->prefix . 'posts';

        try {
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $sql = "DELETE FROM {$table} WHERE ID IN ({$placeholders})";

            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($ids);

            $deleted = $stmt->rowCount();
            return ['status' => 'success', 'deleted' => $deleted];
        } catch (Exception $e) {
            return ['status' => 'error', 'msg' => $e->getMessage()];
        }
    }

    /**
     * Delete suspicious options by IDs
     * 
     * @param array $ids Array of option IDs to delete
     * @return array Result
     */
    public function deleteSuspiciousOptions($ids)
    {
        if (empty($ids) || !is_array($ids)) {
            return ['status' => 'error', 'msg' => 'No IDs provided'];
        }

        $ids = array_filter(array_map('intval', $ids));
        $table = $this->prefix . 'options';

        try {
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $sql = "DELETE FROM {$table} WHERE option_id IN ({$placeholders})";

            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($ids);

            $deleted = $stmt->rowCount();
            return ['status' => 'success', 'deleted' => $deleted];
        } catch (Exception $e) {
            return ['status' => 'error', 'msg' => $e->getMessage()];
        }
    }

    /**
     * Delete suspicious users by IDs
     * 
     * @param array $ids Array of user IDs to delete
     * @return array Result
     */
    public function deleteSuspiciousUsers($ids)
    {
        if (empty($ids) || !is_array($ids)) {
            return ['status' => 'error', 'msg' => 'No IDs provided'];
        }

        $ids = array_filter(array_map('intval', $ids));
        // Di multisite, wp_users dan wp_usermeta selalu global (tanpa blog_id)
        $basePrefix = preg_replace('/\d+_$/', '', $this->prefix);
        $usersTable = $basePrefix . 'users';
        $metaTable = $basePrefix . 'usermeta';

        try {
            $placeholders = implode(',', array_fill(0, count($ids), '?'));

            // Delete from usermeta first
            $sqlMeta = "DELETE FROM {$metaTable} WHERE user_id IN ({$placeholders})";
            $stmtMeta = $this->pdo->prepare($sqlMeta);
            $stmtMeta->execute($ids);

            // Delete from users
            $sqlUsers = "DELETE FROM {$usersTable} WHERE ID IN ({$placeholders})";
            $stmtUsers = $this->pdo->prepare($sqlUsers);
            $stmtUsers->execute($ids);

            $deleted = $stmtUsers->rowCount();
            return ['status' => 'success', 'deleted' => $deleted];
        } catch (Exception $e) {
            return ['status' => 'error', 'msg' => $e->getMessage()];
        }
    }

    /**
     * Delete redirect injections by post IDs
     * 
     * @param array $ids Array of post IDs to delete/clean
     * @return array Result
     */
    public function deleteRedirectInjections($ids)
    {
        // For now, we delete the post entirely if it's infected with redirect
        // In a more advanced version, we could regex replace the content
        return $this->deleteSpamPosts($ids);
    }

    /**
     * Format bytes to human readable
     */
    private function formatBytes($bytes)
    {
        if ($bytes >= 1048576) {
            return round($bytes / 1048576, 2) . ' MB';
        } elseif ($bytes >= 1024) {
            return round($bytes / 1024, 2) . ' KB';
        }
        return $bytes . ' B';
    }

    /**
     * Get last results
     */
    public function getResults()
    {
        return $this->results;
    }
}
