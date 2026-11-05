# webwarden + datz

**Recon & pemindaian kerentanan web yang read-only, sadar-scope, dan buktinya bisa diaudit.**
Satu mesin (`webwarden`), satu konsol terminal penuh warna (`datz.py`), nol dependensi pihak ketiga.

![python](https://img.shields.io/badge/python-3.10%2B-3776ab)
![deps](https://img.shields.io/badge/dependencies-stdlib%20saja-blue)
![license](https://img.shields.io/badge/lisensi-source--available%20%C2%B7%20berbayar-orange)
![platform](https://img.shields.io/badge/platform-Kali%20%C2%B7%20Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-lightgrey)

> **Wajib izin.** Jalankan hanya pada domain yang kamu miliki sendiri atau yang kamu punya
> izin tertulis untuk uji (scope bug bounty, aset kantor, lab milikmu). `--i-am-authorized`
> adalah konfirmasi, bukan formalitas.

---

## Daftar isi

- [Ringkasan](#ringkasan) / [Summary (English)](#summary-english)
- [Instalasi](#instalasi)
- [Mulai cepat](#mulai-cepat)
- [Modul pemindaian](#modul-pemindaian)
- [Perintah](#perintah)
- [datz.py — konsol terminal](#datzpy--konsol-terminal)
- [Lisensi & harga](#lisensi--harga)
- [Batas penggunaan](#batas-penggunaan)
- [Batasan yang jujur](#batasan-yang-jujur)
- [Artefak hasil](#artefak-hasil)
- [Struktur & development](#struktur--development)
- [FAQ](#faq)
- [Penulis](#penulis)

---

## Ringkasan

`webwarden` mengubah satu nama domain menjadi laporan yang siap dikirim ke vendor: rekonsolidasi
subdomain, probing host, header, CORS, cookie/JWT, path sensitif, kebocoran secret di HTML/JS,
drift bundle build, dangling CNAME, kandidat CVE dari versi, sampai probe injeksi non-destruktif
(SQLi / SSTI / XSS / LFI / SSRF / CRLF). Semua permintaan adalah **GET/HEAD**, ada budget request
dan rate limit per host, dan setiap temuan punya **bukti verbatim** di folder `evidence/`.

`datz.py` adalah front-end TUI-nya: satu file, tanpa dependensi, boot animation, panel
konfigurasi, tombol modul, console streaming, tab Temuan/Chains/Recon/Files, dan tombol
pilihan folder output (Kali `~/.datz/runs` atau folder Downloads laptop).

**Yang membedakan dari scanner biasa:**

| | |
|---|---|
| **Read-only by design** | Tidak ada POST, tidak ada payload merusak, tidak ada brute-force login, tidak ada replay credential. Yang opt-in pun tetap GET/HEAD. |
| **Bukti, bukan tebakan** | Tiap temuan menyimpan respons server apa adanya, plus `poc.sh` berisi perintah replikasi yang bisa kamu jalankan ulang sendiri. |
| **Status validasi eksplisit** | Temuan ditandai *verified*, *candidate*, atau *observed*. CVE dari template Nuclei tidak pernah ditulis sebagai "terkonfirmasi". |
| **Scope ketat** | Domain di luar scope ditolak sebelum satu paket pun terkirim. `upload-audit` dan `access-audit` bahkan menolak host publik kecuali benar-benar lab lokal. |
| **Laporan bilingual** | `--lang id` (default, Bahasa Indonesia) atau `--lang en`, di Markdown, HTML, dan JSON. |
| **Offline audit** | Risiko dinilai lokal: heuristik bawaan atau LLM lewat Ollama. Tidak ada body respons yang dikirim ke layanan pihak ketiga. |

## Summary (English)

`webwarden` is a scoped, non-destructive web reconnaissance and vulnerability reporter. One
command performs subdomain discovery, live-host and port probing, header/CORS/cookie analysis,
sensitive-path checks, client-side secret hunting, bundle drift analysis, takeover detection,
version-derived CVE candidates, and read-only injection probing — then writes a Markdown report,
a self-contained HTML report, machine-readable JSON, a reproduction script, and a verbatim
evidence directory. `datz.py` is the same engine inside a single-file animated terminal dashboard.
Everything is stdlib-only, GET/HEAD-only, scope-enforced, and rate-limited. Free use is a 20-day
trial; ongoing commercial use requires a signed licence key.

---

## Instalasi

### 1. Pip (direkomendasikan)

```bash
git clone https://github.com/ziqinsip-png/webwarden.git
cd webwarden
pip install .
webwarden --version
datz --version
```

### 2. Satu file, tanpa install

`datz.py` adalah file tunggal yang bisa berisi mesin di dalamnya (zipapp ter-encode base64,
diverifikasi SHA-256 saat ekstraksi pertama kali). **Repo ini menyimpan template dengan payload
kosong**, supaya source engine hanya ada satu kali di history — bangun dulu file tunggalnya, lalu
jalankan hasil build:

```bash
make datz                                # -> dist/datz.py (engine sudah tertanam)
python3 dist/datz.py                     # dashboard penuh
python3 dist/datz.py --demo              # dashboard dengan data contoh, tanpa scan
python3 dist/datz.py --headless --target example.com --i-am-authorized --full
```

`pip install .` (cara 1) memasang console sebagai `datz`, dan `make install` menaruh file tunggal
beserta engine ke `$(PREFIX)/bin`.

### 3. Kali Linux, ke /usr/bin

```bash
sudo make install               # pasang webwarden + datz ke /usr/local/bin
sudo make install PREFIX=/usr   # atau ke /usr/bin
```

Tidak ada `pip install scapy` atau toolchain lain yang diperlukan — mesinnya hanya memakai
pustaka standar Python.

---

## Mulai cepat

```bash
# Rekon + semua cek read-only default + laporan + audit lokal
webwarden scan example.com --i-am-authorized

# Tambahkan bypass 401/403 dan pengecekan path robots.txt
webwarden scan example.com --i-am-authorized --full

# Rekon saja, tanpa cek kerentanan
webwarden scan example.com --i-am-authorized --recon-only

# Scope lebar dengan budget yang lebih hemat
webwarden scan example.com --i-am-authorized \
    --scope '*.example.com' --scope api.example.net \
    --rate 10 --max-hosts 50 --max-requests 1500

# Audit AI lokal gratis lewat Ollama (tidak ada data keluar mesin)
webwarden scan example.com --i-am-authorized \
    --ai-audit ollama --ai-model qwen2.5:3b

# Cek kesiapan lingkungan dulu
webwarden doctor
```

Python 3.10+. Tidak perlu API key, tidak perlu akun, tidak ada telemetri.

---

## Modul pemindaian

| Modul | Default | Isi |
|---|---|---|
| Subdomain | aktif | DNS brute-force (wordlist bawaan/`--wordlist`), pasif via crt.sh dan subfinder bila tersedia |
| Probing | aktif | HTTP/HTTPS, status, judul, redirect, port pada apex (`--ports`, `--no-ports`) |
| Header & HTTPS | aktif | HSTS, CSP, cookie flags, mTLS hint, matrix keamanan |
| CORS | aktif | Origin reflection, `null`, wildcard — hanya membaca |
| Cookie / JWT | aktif | Uraian offline: claims, `alg:none`, kedaluwarsa, token di URL |
| Path sensitif | aktif | `.env`, `.git/config`, admin panel, backup — GET saja |
| Secrets | aktif | Regex credential di HTML/JS dan path robots.txt; sumber terpotong ditandai |
| Bundles | aktif | Drift build artifact dan source map yang bocor |
| Takeover | aktif | Dangling CNAME ke layanan yang belum diprovision |
| Injection | aktif | SQLi / SSTI / XSS / LFI / SSRF / CRLF, probe non-destruktif (`--no-injection` untuk mematikan) |
| Backdoors | aktif | Jejak web shell pada path yang ada (`--no-backdoors` untuk mematikan) |
| Bypass 401/403 | **opt-in** | Normalisasi path + header proxy, GET saja (`--bypass`) |
| robots.txt paths | **opt-in** | GET ke path `Disallow` untuk cek keterjangkauan (`--robots-paths`) |
| NVD CVE | aktif | Kandidat CVE dari versi yang terlihat di respons |
| Nuclei | **opt-in** | Template safe-match saja; tetap eksplisit karena templatemya mengirim request sendiri (`--nuclei`) |

`--full` mengaktifkan `--bypass` dan `--robots-paths` sekaligus. `--nuclei` tidak pernah ikut
`--full`.

---

## Perintah

| Perintah | Fungsi |
|---|---|
| `webwarden scan <domain>` | Rekon + cek + rantai eksploitasi + laporan + audit lokal dalam satu jalan |
| `webwarden audit <scan.json>` | Menilai ulang hasil yang sudah disimpan, sepenuhnya offline |
| `webwarden diff <run-a> <run-b>` | Membandingkan dua run: muncul, hilang, berubah status |
| `webwarden upload-audit <url>` | Peta read-only permukaan upload pada **lab lokal** (GET/HEAD saja, menolak host publik walau `--lab`) |
| `webwarden access-audit <base-url>` | Uji IDOR/BOLA dua akun milikmu sendiri, GET saja, nilai sesi tidak pernah ditulis ke laporan |
| `webwarden doctor` | Cek DNS, tool lokal, dan prasyarat |
| `webwarden license status` | Sisa hari trial, detail lisensi, sumber kunci |
| `webwarden license activate <kunci>` | Pasang kunci Pro |
| `webwarden license verify <kunci>` | Verifikasi tanda tangan tanpa memasang |
| `webwarden -h` / `webwarden help` | Ikhtisar; `webwarden scan -h` untuk semua opsi beserta contohnya |

Contoh `access-audit` (dua akun uji yang kamu miliki):

```bash
webwarden access-audit https://app.example.com \
    --auth-a 'Cookie: session=TOKEN_A' \
    --auth-b 'Cookie: session=TOKEN_B' \
    --url https://app.example.com/sheets/42 \
    --accounts-owned --i-am-authorized
```

Byte yang identik saat diminta dengan sesi A dicatat sebagai IDOR/BOLA yang terbukti; 401/403
dicatat sebagai kontrol yang lolos. Tidak ada login otomatis, tidak ada enumerasi ID, tidak ada
perubahan permission.

---

## datz.py — konsol terminal

```bash
python3 datz.py                              # dashboard
python3 datz.py --demo                       # tanpa scan, pakai data contoh
python3 datz.py --no-boot --no-weather       # tanpa animasi boot / widget cuaca
python3 datz.py --snapshot --demo --tab findings --width 110 --height 32   # render ke stdout (CI)
python3 datz.py --report                     # ringkasan run terakhir ala CLI lama
python3 datz.py --disclosure                 # draft laporan siap kirim ke vendor
python3 datz.py --diagnose                   # info TTY/terminal/engine untuk diagnosa
python3 datz.py --list-runs                  # daftar run lama
python3 datz.py --license <kunci>            # aktifkan Pro
python3 datz.py --cli scan example.com --i-am-authorized    # teruskan argumen ke engine
```

Tab: `Ringkasan` · `Console` · `Temuan` · `Chains` · `Recon` · `Files`.

Tombol:

| Tombol | Aksi |
|---|---|
| `F1` atau `?` | bantuan |
| `F5` | mulai run |
| `F6` / `Ctrl-C` | stop run |
| `F7` | doctor |
| `F8` | baris perintah engine |
| `F2` | opsi lanjutan (rate, threads, timeout, ports, audit AI) |
| `F4` atau `o` | pilih folder output, lalu buka report |
| `1`–`6` | lompat ke tab |
| `Tab` / `Shift-Tab` | pindah fokus |
| `↑↓←→`, `PgUp/PgDn`, `Home/End` | navigasi dan scroll |
| `Enter` / `Space` | edit field / toggle modul |
| `q` | keluar |

Preset: **Cepat** (secret + bundle), **Standar** (injection, backdoor, takeover, NVD), **Full**
(tambah bypass dan robots.txt), **Recon** (tanpa cek kerentanan).

Pilihan folder output (`F4`): `~/.datz/runs` di Kali, atau `Downloads/datz-runs` di laptop —
berguna kalau kamu menyiapkan scan di satu mesin dan membaca laporan di mesin lain.
Badge lisensi tampil di header kanan (`PRO · customer` atau `TRIAL 19h`).

Jalankan dari terminal asli (GNOME Terminal, kitty, xterm, Windows Terminal). `tmux`/`screen`
didukung; konsol yang tidak mendukung ANSI 256-warna akan keluar lebih dulu dan
`--diagnose` menjelaskan alasannya.

---

## Lisensi & harga

Source-nya publik dan boleh diaudit. **Terbuka bukan berarti gratis.**

| | **Trial** | **Membership** |
|---|---|---|
| Harga | Rp 0 | Rp 39.000 / 30 hari · Rp 99.000 / 90 hari · Rp 299.000 / 365 hari |
| Masa berlaku | 20 hari sejak pertama kali dijalankan | Sesuai paket — kunci punya tanggal kedaluwarsa |
| Modul | Semua modul read-only aktif selama trial | Semua modul, tanpa batas waktu trial |
| Mesin | 1 mesin | 1 mesin, tanpa batas jumlah host yang diperiksa |
| Laporan | Watermark trial di Markdown, HTML, dan `scan.json` | Watermark Pro + nama pelanggan dan ID kunci |
| Audit | `doctor`, `license`, `-h` selalu gratis | Sama |
| Untuk siapa | Pelajar, peneliti, yang mau mencoba dulu | Bug hunter serius, konsultan, tim yang membuat laporan ke klien |

Satu kunci berlaku untuk **webwarden dan netwarden sekaligus** — tidak perlu beli dua.

```bash
webwarden license status          # sisa hari dan tier
webwarden license activate DATZ1.xxxx.xxxx     # pasang kunci yang kamu beli
python3 datz.py --license DATZ1.xxxx.xxxx
```

Kunci berformat `DATZ1.<payload>.<signature>`, ditandatangani dengan **Ed25519** implementasi
stdlib murni (RFC 8032, diverifikasi silang dengan OpenSSL di test suite). Publik key ikut source;
private key hanya dipegang penulis, jadi kunci tidak bisa dibuat sendiri. Trial dicatat di
`~/.datz/state.json` dan bersifat per mesin — install ulang atau ganti nama file tidak menambah
hari. `license.key`, `/etc/datz/<product>.key`, `DATZ_LICENSE`, dan `DATZ_LICENSE_FILE` dibaca
sebelum trial dipakai.

Pemesanan dan harga lengkap: **<https://lisensi.ziqintzy.my.id/>** — di sana ada rincian paket dan
formulernya; pembayarannya manual, kuncinya dikirim setelah transfer.

> **Jujur di muka.** Programnya Python dan source-nya terbuka, jadi pintu lisensi adalah friksi
> dan niat baik, bukan perlindungan yang mustahil dibobol. Lisensi yang kamu beli adalah cara
> mendukung pengembangan alat ini — dan membuat watermark-nya hilang adalah pelanggaran LICENSE,
> bukan sekadar trik.

---

## Batas penggunaan

- **Miliki atau izin tertulis.** Scope harus milikmu atau tercantum dalam programme / MoU.
- **Tidak untuk merusak.** Semua checks GET/HEAD. Tidak ada eksploitasi, tidak ada unggah shell,
  tidak ada perubahan data, tidak ada denial of service.
- **Tidak untuk akun orang lain.** `access-audit` butuh `--accounts-owned` dan hanya
  membandingkan URL objek yang kamu miliki.
- **Rate limit default 5 req/s per host** dengan budget global 4000 request — naikkan hanya
  kalau program mengizinkan.
- **Verifikasi manusia.** Kandidat CVE dan temuan *observed* belum tentu benar. Jangan pernah
  mengirim laporan yang belum kamu buka sendiri bukti di `evidence/`.
- **Laporan bersifat privat.** `evidence/` menyimpan respons server apa adanya, termasuk password
  dan token milik orang lain. Simpan dengan mode 600, redaksi sesuai policy programme.
- **Patuhi hukum setempat**, termasuk UU ITE di Indonesia. Penulis tidak bertanggung jawab atas
  penyalahgunaan.

---

## Batasan yang jujur

- Ini **bukan** pengganti scanner interaktif penuh. Tidak ada authenticated crawling, tidak ada
  manipulasi state, tidak ada race condition testing, tidak ada weaponization.
- **Tidak memeriksa jaringan dalam.** Tidak ada binding socket, scan UDP, atau fingerprint stack.
- Kandidat CVE **diturunkan dari versi yang terlihat**, bukan dari PoC yang berhasil. Bisa
  false positive karena distro sudah menambal tanpa mengganti versi.
- Deteksi injeksi **berbasis sinyal respons**, jadi endpoint dengan normalisasi error agresif atau
  WAF yang selalu mengembalikan 200 bisa meleset.
- Subdomain takeover butuh CNAME yang benar-benar menggantung; layanan yang mengembalikan
  halaman parkir tidak akan dilaporkan sebagai takeover.
- `upload-audit` dan `access-audit` sengaja dikunci ke lab / akun milik sendiri supaya tidak bisa
  dipakai sebagai alat akses ilegal.
- Hasilnya selengkap-lengkapnya **seluas scope yang kamu beri**. Tidak ada klaim "pasti semua
  ketemu".

---

## Artefak hasil

Satu run menulis folder baru berisi:

```
report.md        laporan Markdown, bilingual, dengan blok bukti
report.html      satu file mandiri: grafik severity, chain, matriks header, filter temuan
scan.json        hasil terstruktur untuk audit ulang, diff, atau pipeline
poc.sh           perintah replikasi read-only per temuan, siap diaudit
evidence/        respons server verbatim (TIDAK diredaksi, TIDAK dipotong)
audit/           hasil audit lokal (heuristik atau Ollama)
disclosure.md    draft laporan siap kirim ke vendor, dibuat dengan --disclosure
```

Semua berada di folder run pilihan kamu (`~/.datz/runs` atau `Downloads/datz-runs`) dan
mencetak stempel lisensi di dalam laporan.

---

## Struktur & development

```
webwarden/            mesin (stdlib only)
  cli.py              parser, perintah, gerbang lisensi
  licensing.py        Ed25519 RFC 8032, trial 20 hari, aktivasi kunci
  recon.py checks.py injection.py backdoors.py bundles.py secrets.py
  chains.py cve.py nuclei.py takeover.py evidence.py poc.py
  report.py html.py audit.py scenario.py diffing.py
datz.py               konsol TUI satu file, memuat engine dari payload
pack_datz.py          embedding engine ke datz.py (buat dist/datz.py)
tests/                286 test unittest, tanpa dependensi eksternal
```

```bash
make all        # engine zipapp + dist/datz.py (make tanpa target = ikhtisar)
make test       # jalankan seluruh suite
make lite       # build tanpa kunci (mode trial)
make pro LICENSE_KEY=DATZ1.xxxx.xxxx   # pasang kunci Pro ke mesin ini
make status     # tier, sisa hari, sumber kunci
make key CUSTOMER="Nama" DAYS=365       # (penerbit) tanda tangani kunci baru
make install    # pasang ke /usr/local/bin (PREFIX=... untuk ganti)
make clean
```

`make key` hanya bekerja kalau `DATZ_SIGNING_KEY` terisi di environment, dan kunci privat
tidak pernah ikut repo.

Test dijalankan dengan `python -m unittest tests.test_...`; lihat `make test`.

---

## FAQ

**Trial-nya habis, tapi aku cuma butuh `doctor`.** `doctor`, `license`, `-h`/`help`, dan
`--list-runs` tidak pernah dikunci. Perintah yang mengirim request ke target yang berhenti.

**Aku instal ulang, hari trial-nya reset?** Tidak. `~/.datz/state.json` mencatat waktu pertama
kali program berjalan; trial bersifat per mesin, bukan per install.

**Kenapa jam sistem tidak boleh mundur?** Gate menolak saat jam melompat ke belakang, karena itu
cara paling mudah memanipulasi trial. Kalau kamu memang perlu berpindah zona waktu, aktifkan
lisensi.

**Bisa dipakai di Windows?** `datz.py` jalan di Windows Terminal dengan Python 3.10+. Untuk hasil
paling stabil tetap Kali/WSL2.

**Dataku dikirim ke mana?** Tidak ke mana-mana. Audit AI default memakai heuristik lokal; opsi
`--ai-audit ollama` berbicara ke Ollama di mesin kamu. Satu-satunya request keluar adalah ke
target yang kamu scan (dan crt.sh untuk rekon pasif).

**Boleh ikut belajar dari source-nya?** Sangat boleh. Baca `checks.py` dan `chains.py`, jalankan
di lab milikmu sendiri, dan bandingkan temuan dengan realitas.

---

## Penulis

**Ahmad Roziqin** — <https://ziqintzy.my.id> · <https://portofolio.ziqintzy.my.id> · GitHub [@ziqinsip-png](https://github.com/ziqinsip-png)

Lisensi, pertanyaan komersial, atau laporan bug: buka halaman kontak di portofolio di atas, atau
buat issue di repo ini.
