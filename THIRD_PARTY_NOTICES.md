# Pemberitahuan Pihak Ketiga (Third-Party Notices)

RadarKit menggunakan komponen pihak ketiga berikut:

---

## 1. Tiny File Manager v2.6

- **File:** `xtool.php`
- **Lisensi:** GNU General Public License v3.0 (GPLv3)
- **Repositori:** https://github.com/prasathmani/tinyfilemanager
- **Hak Cipta:** © CCP Programmers / H3K
- **Modifikasi:**
  - Rename file dari `tinyfilemanager.php` ke `xtool.php`
  - Penambahan SSO Bridge untuk integrasi autentikasi dengan RadarKit (baris 228-259)
  - Konfigurasi default disesuaikan untuk mode portabel

---

## 2. Adminer

- **File:** `adminer-core.php`
- **Lisensi:** Apache License 2.0 / GNU General Public License v2.0 (GPLv2)
- **Sumber:** https://www.adminer.org
- **Hak Cipta:** © Jakub Vrána
- **Modifikasi:** Tidak ada modifikasi. File digunakan apa adanya.
- **Catatan:** Diakses melalui `bantuan.php` sebagai SSO bridge.

---

## Lisensi Proyek

RadarKit secara keseluruhan dilisensikan di bawah **GNU General Public License v3.0 (GPLv3)** untuk memastikan kompatibilitas dengan Tiny File Manager.

Lihat file [LICENSE](LICENSE) untuk teks lisensi lengkap.
