# 🛡️ RadarKit v4.5

**Toolkit Portabel untuk Deteksi & Pembersihan Malware WordPress**

RadarKit adalah alat keamanan berbasis PHP yang dirancang untuk mendeteksi, menganalisis, dan membersihkan malware dari situs WordPress yang terinfeksi — khususnya judi online (judol), Japanese Keyword Hack, Pharma Hack, dan backdoor.

> Cukup upload ke server, akses via browser, dan mulai scanning. Tidak perlu instalasi.

---

## ✨ Fitur Utama

| Fitur | Deskripsi |
|-------|-----------|
| 🔍 **Smart Scanner** | Deteksi malware dengan heuristic scoring, entropy analysis, dan contextual weighting |
| 🧬 **Signature Database** | 191+ pattern: backdoor, gambling, pharma, Japanese/Chinese SEO spam |
| 🫀 **Operasi Jantung** | Auto-replace WordPress core files tanpa kehilangan data |
| 🗄️ **Database Scanner** | Scan `wp_posts`, `wp_options`, `wp_users` untuk konten spam & admin asing |
| 📁 **File Manager** | Kelola file server via XTool (Tiny File Manager terintegrasi) |
| 🔌 **Database Bridge** | Akses database via Adminer dengan SSO otomatis |
| 📊 **PDF Report** | Export laporan keamanan sebagai PDF profesional |
| 🌐 **Cloud Signatures** | Database signature terenkripsi, di-update otomatis dari cloud |
| 🏢 **Multisite Support** | Deteksi & scan WordPress Multisite |

---

## 🚀 Instalasi

### 1. Upload
Upload seluruh folder `radarkit/` ke root directory situs WordPress yang terinfeksi:
```
public_html/
├── wp-admin/
├── wp-content/
├── wp-includes/
├── wp-config.php
└── radarkit/          ← Upload di sini
    ├── radar.php
    ├── radar_config.php
    ├── radar_signatures.php
    ├── radar_db.php
    ├── bantuan.php
    ├── xtool.php
    └── adminer-core.php
```

### 2. Konfigurasi
Salin `radar_config.sample.php` → `radar_config.php`, lalu ganti password:
```php
define('RADAR_PASSPHRASE', 'password-anda-yang-kuat');
```

> Cukup ganti password saja — cloud signature akan otomatis terhubung.

### 3. Akses
Buka di browser:
```
https://domain-klien.com/radarkit/radar.php
```

---

## 📖 Panduan Penggunaan

### Langkah 1: Pasang Halaman Maintenance

Sebelum memulai proses pembersihan, pasang halaman maintenance agar pengunjung tidak melihat konten malware selama proses berlangsung.

1. **Rename** file `index.php` asli di root WordPress menjadi `index.php.bak`
2. **Copy** file `radarkit/index.html` ke root WordPress (`public_html/index.html`)
3. Pengunjung sekarang melihat halaman "Pemeliharaan Keamanan" yang profesional
4. Setelah pembersihan selesai, **hapus** `index.html` dan **rename kembali** `index.php.bak` → `index.php`

```
public_html/
├── index.php      ← Rename jadi index.php.bak
├── index.html     ← Copy dari radarkit/index.html
└── radarkit/
```

> 💡 Apache/Nginx akan memprioritaskan `index.html` di atas `index.php` secara default.

---

### Langkah 2: Login ke RadarKit

Buka `https://domain-klien.com/radarkit/radar.php` di browser, masukkan password yang telah dikonfigurasi.

---

### Langkah 3: Sync Core (WAJIB Sebelum Scan)

> ⚠️ **PENTING:** Langkah ini WAJIB dilakukan sebelum scanning agar hasil deteksi akurat!

**Sync Core** mengunduh file WordPress asli (bersih) langsung dari wordpress.org sesuai versi yang terdeteksi, dan menyimpannya di folder `fresh_core/`. RadarKit menggunakan file ini sebagai **baseline pembanding** untuk mendeteksi file yang telah dimodifikasi oleh malware.

**Cara melakukan Sync Core:**
1. Di dashboard, RadarKit akan mendeteksi versi WordPress secara otomatis
2. Klik tombol **"Sync Core"** atau **"Download WP Core"**
3. Tunggu proses download dan ekstraksi selesai
4. Status core akan berubah menjadi **"Synchronized"** ✅

**Tanpa Sync Core:**
- Scanner tidak bisa membandingkan file core → file terinfeksi di `wp-admin/` dan `wp-includes/` mungkin **tidak terdeteksi**
- Fitur **Operasi Jantung** (replace core) tidak bisa dijalankan

---

### Langkah 4: Jalankan File Scan

Setelah Sync Core selesai, jalankan scan:

1. Klik tombol **"Start Scan"** di dashboard
2. RadarKit akan memindai seluruh file di WordPress secara rekursif
3. Setiap file dinilai dengan **heuristic scoring** berdasarkan:
   - Fungsi berbahaya (`eval`, `base64_decode`, `shell_exec`, dll.)
   - Pattern backdoor/webshell (regex matching)
   - Keyword spam (gambling, pharma, Japanese/Chinese)
   - Entropy analysis (deteksi kode obfuscated)
   - Perbandingan hash MD5 dengan fresh core
4. Hasil scan ditampilkan dalam tabel dengan **skor ancaman** dan **alasan deteksi**

**Cara membaca hasil scan:**
| Skor | Level | Tindakan |
|:----:|:-----:|:---------|
| 0-20 | 🟢 Safe | Kemungkinan false positive, review manual |
| 21-50 | 🟡 Suspicious | Periksa file secara manual |
| 51-80 | 🟠 Dangerous | Kemungkinan besar terinfeksi |
| 81+ | 🔴 Critical | Hampir pasti malware — hapus atau replace |

**Preview Kode & Highlight Berbahaya:**

Setiap file yang terdeteksi mencurigakan dilengkapi dengan **tag highlight** — potongan kode atau keyword berbahaya yang ditemukan di dalam file tersebut. Contoh highlight yang mungkin muncul:

| Tag Highlight | Jenis Ancaman |
|:---|:---|
| `eval`, `base64_decode`, `gzinflate` | Kode terenkripsi/obfuscated |
| `shell_exec`, `system`, `passthru` | Eksekusi command server |
| `$_POST`, `$_REQUEST` | Backdoor input handler |
| `wp_vcd`, `create_function` | Malware WordPress populer |
| `display:none`, `visibility:hidden` | Link spam tersembunyi (SEO hack) |
| `激安`, `偽ブランド`, keyword judi | Japanese/Chinese/Gambling keyword hack |
| Domain mencurigakan | Injeksi script dari domain malicious |

Highlight ini membantu Anda memutuskan tindakan tanpa harus membuka file secara manual — cukup lihat tag-nya untuk mengetahui **jenis malware** yang menginfeksi file tersebut.

> 💡 **Tips:** Jika highlight menunjukkan `eval` + `base64_decode` di file `wp-content/`, file tersebut hampir pasti backdoor dan aman untuk dihapus. Namun jika muncul di `wp-admin/` atau `wp-includes/`, gunakan **Operasi Jantung** untuk me-replace file core.

---

### Langkah 5: Scan Database

Selain file, malware sering menyisipkan konten spam ke database WordPress:

1. Navigasi ke tab **"Database Scanner"**
2. Jalankan scan untuk memeriksa:
   - **Posts** — Artikel/halaman berisi keyword judi, pharma, atau link spam
   - **Options** — Opsi WordPress yang diinjeksi malware (misal: `wp_vcd`)
   - **Users** — Admin baru yang dibuat oleh hacker
   - **Redirects** — Injeksi redirect ke situs judi/spam
3. Pilih item yang terinfeksi → Hapus langsung dari dashboard

---

### Langkah 6: Operasi Jantung (Replace Core)

Jika file-file inti WordPress (`wp-admin/`, `wp-includes/`) terinfeksi:

1. Klik tombol **"Operasi Jantung"** / **"Replace Core"**
2. RadarKit akan **mengganti seluruh file core** dengan versi bersih dari `fresh_core/`
3. Proses ini **tidak menghapus**:
   - `wp-content/` (tema, plugin, upload Anda)
   - `wp-config.php` (konfigurasi database)
   - `.htaccess` (konfigurasi server)

> ⚠️ Sync Core WAJIB sudah berhasil sebelum menjalankan operasi ini.

---

### Langkah 7: Bersihkan File Terinfeksi

Untuk file di luar core (misal di `wp-content/`):

1. Dari hasil scan, centang file yang terinfeksi
2. Klik **"Delete Selected"** untuk menghapus secara bulk
3. Atau gunakan **XTool (File Manager)** untuk review dan hapus file secara manual

> 💡 Gunakan XTool juga untuk memeriksa folder `wp-content/uploads/` — malware sering menyamar sebagai file gambar (`.php` di folder upload).

---

### Langkah 8: Export Laporan

Setelah pembersihan selesai:

1. Klik tombol **"Export PDF"** dari dashboard
2. RadarKit menghasilkan laporan keamanan profesional berisi:
   - Ringkasan ancaman yang ditemukan
   - Daftar file yang terinfeksi & tindakan yang diambil
   - Status core integrity
3. Gunakan laporan ini untuk dokumentasi atau bukti ke klien

---

### Langkah 9: Post-Cleanup

Setelah pembersihan selesai, lakukan langkah-langkah berikut:

1. **Hapus halaman maintenance** — Hapus `index.html` dari root, rename `index.php.bak` kembali ke `index.php`
2. **Hapus folder `radarkit/`** — WAJIB! Jangan tinggalkan tool keamanan di server produksi
3. **Ganti semua password** — Password WordPress admin, FTP, database, dan hosting
4. **Update WordPress** — Core, tema, dan semua plugin ke versi terbaru
5. **Cek Google Search Console** — Hapus URL spam dari index Google jika ada

---

## 📂 Struktur File

```
radarkit/
├── radar.php                 # Dashboard utama & scanner engine
├── radar_config.php          # Konfigurasi (password) — JANGAN commit!
├── radar_config.sample.php   # Template konfigurasi
├── radar_signatures.php      # SignatureProvider + cloud engine
├── radar_db.php              # Scanner database WordPress
├── index.html                # Halaman maintenance (pasang di root WP)
├── bantuan.php               # SSO bridge ke Adminer
├── xtool.php                 # File manager (fork Tiny File Manager)
├── adminer-core.php          # Database manager
├── fresh_core/               # WordPress core bersih (diisi oleh Sync Core)
├── LICENSE                   # GPLv3
├── THIRD_PARTY_NOTICES.md    # Atribusi komponen pihak ketiga
└── README.md                 # Dokumentasi ini
```

---

## 🔒 Keamanan

- **Autentikasi** — Login dengan passphrase sebelum akses fitur apapun
- **IP Lockdown** — Session terkunci ke IP address untuk mencegah hijacking
- **Session Regeneration** — Token session di-regenerate setiap login
- **SSO Bridge** — Semua tool (XTool, Adminer) hanya bisa diakses setelah login RadarKit

> ⚠️ **PENTING:** Selalu hapus folder `radarkit/` dari server klien setelah proses pembersihan selesai!

---

## ☁️ Cloud Signatures

RadarKit secara otomatis mengambil database signature terenkripsi dari cloud saat pertama kali dijalankan:

- **191+ pattern deteksi** — backdoor, gambling, pharma, Japanese/Chinese SEO spam
- **Enkripsi AES-256-CBC** — data signature dienkripsi end-to-end
- **Cache otomatis** — signature di-cache selama 24 jam (terenkripsi di server)
- **Zero config** — tidak perlu konfigurasi apapun, langsung jalan

> Jika koneksi cloud gagal dan tidak ada cache, scanner akan menampilkan peringatan.

---

## 📜 Lisensi

RadarKit dilisensikan di bawah **GNU General Public License v3.0 (GPLv3)**.

Lihat file [LICENSE](LICENSE) untuk detail lengkap.

### Komponen Pihak Ketiga

- **Tiny File Manager v2.6** — GPLv3 ([repo](https://github.com/prasathmani/tinyfilemanager))
- **Adminer** — Apache 2.0 / GPLv2 ([website](https://www.adminer.org))

Lihat [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) untuk informasi lengkap.

---

## 🤝 Kontribusi

Kontribusi sangat diterima! Silakan buat Pull Request atau buka Issue di repositori ini.

---

## Developer Info

Beberapa tools lainya dari kami:
- <a href="https://cekhape.com"><b>CekHape</b></a> - Tools cek hp bekas untuk transparansi jual beli hp second.

<p align="center">
  <b>RadarKit</b> — Dibuat untuk melindungi WordPress Indonesia 🇮🇩
</p>

