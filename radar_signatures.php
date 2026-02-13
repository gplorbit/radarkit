<?php
/**
 * 🛡️ Radar Signatures Database v4.5
 * 
 * CATATAN: File ini berisi STRUKTUR KOSONG sebagai fallback.
 * Semua data signature dimuat dari Cloud via SignatureProvider.
 * 
 * Untuk informasi lebih lanjut, lihat:
 * - SignatureProvider::getSignatures() di file ini
 * - radar_config.php → RADAR_CLOUD_SIGNATURE_URL
 * 
 * @package RadarKit
 * @version 4.5
 * @updated 2026-02-13
 */

class RadarSignatures
{
    /** Pattern fungsi berbahaya — Dimuat dari cloud */
    public static $dangerousFunctions = [];

    /** Pattern regex backdoor/webshell — Dimuat dari cloud */
    public static $backdoorPatterns = [];

    /** Keyword Gambling/Judi Online — Dimuat dari cloud */
    public static $gamblingKeywords = [];

    /** Keyword Pharma Hack — Dimuat dari cloud */
    public static $pharmaKeywords = [];

    /** Japanese Spam Keywords — Dimuat dari cloud */
    public static $japaneseSpamKeywords = [];

    /** Chinese Spam Keywords — Dimuat dari cloud */
    public static $chineseSpamKeywords = [];

    /** Suspicious file names — Dimuat dari cloud */
    public static $suspiciousFileNames = [];

    /** Suspicious htaccess patterns — Dimuat dari cloud */
    public static $htaccessPatterns = [];

    /** Malicious CDN/domain patterns — Dimuat dari cloud */
    public static $evilDomains = [];

    /** Database spam patterns — Dimuat dari cloud */
    public static $databaseSpamPatterns = [];
}

/**
 * SignatureProvider - Cloud Signature Engine v2.0
 * 
 * Mengambil signature dari Cloud (Cloudflare Worker / URL lain),
 * mendekripsi data AES-256-CBC, dan menyimpan cache terenkripsi.
 * 
 * Fallback chain:
 * 1. Cloud (fresh fetch + dekripsi)
 * 2. Cache terenkripsi lokal (jika cloud gagal)
 * 3. Signature lokal kosong + peringatan (last resort)
 * 
 * @package RadarKit
 * @version 2.0
 * @updated 2026-02-13
 */
class SignatureProvider
{
    // === Default Cloud Configuration ===
    // Digunakan jika radar_config.php tidak meng-override
    // Ganti key ini saat transisi ke model monetisasi
    private static $defaultCloudUrl = 'https://radarkit-sigs.jaka-write.workers.dev/';
    private static $defaultEncKey = 'rk-2026-x7f9a3c1e5b8d2f4';

    private static $cloudCache = null;
    private static $cacheFile = __DIR__ . '/.sig_cache.enc';
    private static $cacheTTL = 86400; // 24 jam
    private static $lastError = null;
    private static $source = 'none'; // Track dari mana data berasal

    // Struktur kosong sebagai fallback terakhir
    private static $emptySignatures = [
        'dangerousFunctions' => [],
        'backdoorPatterns' => [],
        'gamblingKeywords' => [],
        'pharmaKeywords' => [],
        'japaneseSpamKeywords' => [],
        'chineseSpamKeywords' => [],
        'suspiciousFileNames' => [],
        'htaccessPatterns' => [],
        'evilDomains' => [],
        'databaseSpamPatterns' => [],
    ];

    /**
     * Mendapatkan semua signatures
     * 
     * Prioritas: Cloud → Cache → Empty (dengan peringatan)
     * 
     * @return array Signature database
     */
    public static function getSignatures()
    {
        // Jika sudah di-cache di memori (same request), langsung return
        if (self::$cloudCache !== null) {
            return self::$cloudCache;
        }

        // Resolve cloud URL: config → hardcoded default
        $cloudUrl = self::resolveCloudUrl();
        if (empty($cloudUrl)) {
            self::$source = 'local_fallback';
            self::$lastError = 'Cloud URL tidak tersedia. Menggunakan database lokal.';
            $local = self::getLocalSignatures();
            self::$cloudCache = $local;
            return $local;
        }

        // Coba ambil dari cloud
        $cloud = self::fetchCloudSignatures();
        if ($cloud) {
            self::$source = 'cloud';
            self::$cloudCache = $cloud;
            return $cloud;
        }

        // Fallback: coba cache terenkripsi
        $cached = self::readEncryptedCache();
        if ($cached) {
            self::$source = 'cache';
            self::$cloudCache = $cached;
            return $cached;
        }

        // Last resort: lokal (kemungkinan kosong)
        self::$source = 'local_empty';
        self::$lastError = self::$lastError ?: 'Tidak dapat terhubung ke cloud dan tidak ada cache tersedia.';
        $local = self::getLocalSignatures();
        self::$cloudCache = $local;
        return $local;
    }

    /**
     * Resolve Cloud URL: config → hardcoded default
     * 
     * @return string URL cloud signature
     */
    private static function resolveCloudUrl()
    {
        if (defined('RADAR_CLOUD_SIGNATURE_URL') && !empty(RADAR_CLOUD_SIGNATURE_URL)) {
            return RADAR_CLOUD_SIGNATURE_URL;
        }
        return self::$defaultCloudUrl;
    }

    /**
     * Resolve Encryption Key: config → hardcoded default
     * 
     * @return string Encryption key
     */
    private static function resolveEncryptionKey()
    {
        if (defined('RADAR_ENCRYPTION_KEY') && !empty(RADAR_ENCRYPTION_KEY)) {
            return RADAR_ENCRYPTION_KEY;
        }
        return self::$defaultEncKey;
    }

    /**
     * Mengambil signature dari database lokal (fallback)
     * Setelah migrasi cloud selesai, array ini akan kosong.
     */
    private static function getLocalSignatures()
    {
        return [
            'dangerousFunctions' => RadarSignatures::$dangerousFunctions,
            'backdoorPatterns' => RadarSignatures::$backdoorPatterns,
            'gamblingKeywords' => RadarSignatures::$gamblingKeywords,
            'pharmaKeywords' => RadarSignatures::$pharmaKeywords,
            'japaneseSpamKeywords' => RadarSignatures::$japaneseSpamKeywords,
            'chineseSpamKeywords' => RadarSignatures::$chineseSpamKeywords,
            'suspiciousFileNames' => RadarSignatures::$suspiciousFileNames,
            'htaccessPatterns' => RadarSignatures::$htaccessPatterns,
            'evilDomains' => RadarSignatures::$evilDomains,
            'databaseSpamPatterns' => RadarSignatures::$databaseSpamPatterns,
        ];
    }

    /**
     * Fetch signature dari cloud (Cloudflare Worker / URL lain)
     * 
     * Mendukung dua format response:
     * 1. JSON terenkripsi (memerlukan RADAR_ENCRYPTION_KEY)
     * 2. JSON plain-text (untuk development/testing)
     * 
     * @return array|null Signature data atau null jika gagal
     */
    private static function fetchCloudSignatures()
    {
        $cloudUrl = self::resolveCloudUrl();

        $ctx = stream_context_create([
            'http' => [
                'timeout' => 10,
                'ignore_errors' => true,
                'user_agent' => 'RadarKit/4.5',
                'header' => self::buildRequestHeaders()
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true
            ]
        ]);

        $response = @file_get_contents($cloudUrl, false, $ctx);

        if ($response === false) {
            self::$lastError = 'Cloud signature: Gagal terhubung ke ' . $cloudUrl;
            return null;
        }

        // Cek HTTP status code
        if (isset($http_response_header) && is_array($http_response_header)) {
            $statusLine = $http_response_header[0] ?? '';
            if (preg_match('/\s(\d{3})\s/', $statusLine, $m)) {
                $httpCode = intval($m[1]);
                if ($httpCode !== 200) {
                    self::$lastError = "Cloud signature: HTTP Error {$httpCode}";
                    return null;
                }
            }
        }

        // Coba dekripsi jika encryption key tersedia
        $data = self::decryptResponse($response);

        if ($data && is_array($data) && self::validateSignatureStructure($data)) {
            // Simpan ke cache terenkripsi
            self::writeEncryptedCache($data);
            return $data;
        }

        self::$lastError = 'Cloud signature: Data tidak valid atau kunci dekripsi salah.';
        return null;
    }

    /**
     * Dekripsi response dari cloud
     * 
     * @param string $response Raw response dari cloud
     * @return array|null Data yang sudah didekripsi
     */
    private static function decryptResponse($response)
    {
        // Resolve encryption key: config → hardcoded default
        $encKey = self::resolveEncryptionKey();
        if (!empty($encKey)) {
            $decrypted = self::decryptAES256($response, $encKey);
            if ($decrypted) {
                $data = json_decode($decrypted, true);
                if ($data && is_array($data)) {
                    return $data;
                }
            }
        }

        // Fallback: coba parse sebagai plain JSON (development mode)
        $data = json_decode($response, true);
        if ($data && is_array($data)) {
            return $data;
        }

        return null;
    }

    /**
     * Dekripsi data menggunakan AES-256-CBC
     * 
     * Format data terenkripsi: base64(IV + encrypted_data)
     * IV = 16 bytes pertama
     * 
     * @param string $encryptedData Data terenkripsi (base64)
     * @param string $key Encryption key
     * @return string|false Data yang sudah didekripsi atau false
     */
    private static function decryptAES256($encryptedData, $key)
    {
        if (!function_exists('openssl_decrypt')) {
            self::$lastError = 'OpenSSL extension tidak tersedia untuk dekripsi.';
            return false;
        }

        $raw = base64_decode($encryptedData, true);
        if ($raw === false || strlen($raw) < 16) {
            return false;
        }

        $iv = substr($raw, 0, 16);
        $encrypted = substr($raw, 16);
        $keyHash = hash('sha256', $key, true);

        $decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', $keyHash, OPENSSL_RAW_DATA, $iv);
        return $decrypted;
    }

    /**
     * Enkripsi data menggunakan AES-256-CBC
     * 
     * @param string $plainData Data yang akan dienkripsi
     * @param string $key Encryption key
     * @return string Data terenkripsi (base64)
     */
    public static function encryptAES256($plainData, $key)
    {
        $iv = openssl_random_pseudo_bytes(16);
        $keyHash = hash('sha256', $key, true);
        $encrypted = openssl_encrypt($plainData, 'aes-256-cbc', $keyHash, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $encrypted);
    }

    /**
     * Simpan cache terenkripsi ke disk
     */
    private static function writeEncryptedCache($data)
    {
        $cachePayload = json_encode([
            'timestamp' => time(),
            'version' => '2.0',
            'data' => $data
        ]);

        // Enkripsi cache
        $encKey = self::resolveEncryptionKey();
        if (!empty($encKey)) {
            $encrypted = self::encryptAES256($cachePayload, $encKey . '_cache');
            @file_put_contents(self::$cacheFile, $encrypted);
        } else {
            // Development mode: simpan plain
            @file_put_contents(self::$cacheFile, $cachePayload);
        }
    }

    /**
     * Baca cache terenkripsi dari disk
     */
    private static function readEncryptedCache()
    {
        if (!file_exists(self::$cacheFile)) {
            return null;
        }

        $raw = @file_get_contents(self::$cacheFile);
        if (!$raw) {
            return null;
        }

        $cachePayload = null;

        // Coba dekripsi
        $encKey = self::resolveEncryptionKey();
        if (!empty($encKey)) {
            $decrypted = self::decryptAES256($raw, $encKey . '_cache');
            if ($decrypted) {
                $cachePayload = $decrypted;
            }
        }

        // Fallback: coba parse sebagai plain JSON
        if (!$cachePayload) {
            $cachePayload = $raw;
        }

        $cache = json_decode($cachePayload, true);
        if (!$cache || !isset($cache['data']) || !isset($cache['timestamp'])) {
            return null;
        }

        // Cek apakah cache masih valid (TTL)
        $age = time() - $cache['timestamp'];
        if ($age < self::$cacheTTL) {
            self::$lastError = null; // Cache valid, hapus error
            return $cache['data'];
        }

        // Cache expired, tapi tetap bisa dipakai sebagai fallback
        self::$lastError = "Cache signature sudah expired ({$age}s). Menggunakan cache lama.";
        return $cache['data'];
    }

    /**
     * Validasi bahwa struktur data signature lengkap
     */
    private static function validateSignatureStructure($data)
    {
        $requiredKeys = ['dangerousFunctions', 'backdoorPatterns', 'gamblingKeywords'];
        foreach ($requiredKeys as $key) {
            if (!isset($data[$key])) {
                return false;
            }
        }
        return true;
    }

    /**
     * Build request headers untuk cloud fetch
     */
    private static function buildRequestHeaders()
    {
        $headers = "Accept: application/json\r\n";

        // Kirim API key jika dikonfigurasi (untuk Cloudflare Worker auth)
        if (defined('RADAR_API_KEY') && !empty(RADAR_API_KEY)) {
            $headers .= "X-Radar-Key: " . RADAR_API_KEY . "\r\n";
        }

        return $headers;
    }

    /**
     * Merge signature cloud ke lokal (cloud OVERRIDE, bukan menambahkan)
     * Cloud adalah sumber utama, lokal hanya fallback
     */
    private static function mergeSignatures($local, $cloud)
    {
        foreach ($cloud as $key => $values) {
            if (isset($local[$key]) && is_array($values)) {
                $local[$key] = array_merge($local[$key], $values);
            } else {
                $local[$key] = $values;
            }
        }
        return $local;
    }

    /**
     * Info status cloud signature (untuk UI dashboard)
     */
    public static function getCloudStatus()
    {
        $cloudUrl = self::resolveCloudUrl();
        $encKey = self::resolveEncryptionKey();

        $status = [
            'enabled' => !empty($cloudUrl),
            'encrypted' => !empty($encKey),
            'source' => self::$source,
            'cached' => file_exists(self::$cacheFile),
            'cache_age' => null,
            'error' => self::$lastError,
            'url' => $cloudUrl ? preg_replace('/\/\/(.{8}).*@/', '//$1***@', $cloudUrl) : ''
        ];

        if ($status['cached']) {
            $raw = @file_get_contents(self::$cacheFile);
            if ($raw) {
                // Coba dekripsi untuk mendapatkan timestamp
                $cachePayload = null;
                if (!empty($encKey)) {
                    $cachePayload = self::decryptAES256($raw, $encKey . '_cache');
                }
                if (!$cachePayload) {
                    $cachePayload = $raw;
                }
                $cache = json_decode($cachePayload, true);
                if ($cache && isset($cache['timestamp'])) {
                    $status['cache_age'] = time() - $cache['timestamp'];
                }
            }
        }

        return $status;
    }

    /**
     * Hapus cache (untuk troubleshooting)
     */
    public static function clearCache()
    {
        if (file_exists(self::$cacheFile)) {
            @unlink(self::$cacheFile);
            return true;
        }
        return false;
    }

    /**
     * Mendapatkan error terakhir
     */
    public static function getLastError()
    {
        return self::$lastError;
    }
}
