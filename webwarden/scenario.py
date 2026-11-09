"""Hypothetical attacker narrative for the report.

This module only re-tells conditions that the scan already observed. It never
contains payloads, commands, or executed exploitation steps; the narrative is
explicit about where the read-only tool stopped.
"""

from __future__ import annotations

from .models import SEVERITY_ORDER

BOUNDARY = (
    "Simulasi defensif: alur di bawah menjelaskan dampak yang mungkin terjadi "
    "bila temuan ini nyata. Tidak ada payload, command, upload, atau langkah "
    "eksploitasi yang dijalankan oleh scan ini; verifikasi berhenti di bukti "
    "read-only yang tercatat di finding."
)

STORY_PREFIX = (
    "Cerita berikut adalah skenario hipotetis dari sudut pandang penyerang, "
    "disusun dari kondisi yang sudah teramati. Tujuannya agar pembaca melihat "
    "dampak nyata dan titik henti pengujian, bukan panduan menyerang."
)

SCENARIOS: dict[str, dict] = {
    "sqli": {
        "title": "SQL injection → data exposure",
        "story": [
            "Penyerang memetakan endpoint dan parameter yang menerima input, "
            "lalu membandingkan respons normal dengan respons yang memicu SQL "
            "error atau selisih perilaku.",
            "Kalau pola itu konsisten, penyerang menyimpulkan input masuk ke "
            "query database tanpa parameterisasi yang benar.",
            "Dari titik itu, penyerang biasanya mencoba membaca tabel "
            "pengguna, mengambil hash password atau token sesi, dan mengecek "
            "apakah hak akses database mengizinkan perubahan data.",
            "Dampak terburuknya bukan cuma bocornya satu halaman: kredensial "
            "yang sama sering dipakai ulang, sehingga akun lain bisa ikut "
            "terambil alih.",
            "Scan ini berhenti setelah pola injection terbukti; tidak ada data "
            "yang diekstrak dan tidak ada data yang diubah.",
        ],
        "impact": "Kebocoran data pengguna, bypass login, atau perubahan data "
                  "tergantung hak akses akun database aplikasi.",
        "confirm": [
            "Pastikan parameter yang sama menghasilkan selisih respons yang "
            "stabil pada dua request terpisah.",
            "Cek log aplikasi/database apakah query yang dihasilkan memang "
            "menggabungkan input pengguna.",
            "Uji di akun uji milik sendiri, bukan data pengguna nyata.",
        ],
        "tools": ["curl / browser DevTools", "Burp Suite Repeater",
                  "sqlmap (hanya oleh pemilik scope, tidak dipakai di sini)"],
    },
    "xss": {
        "title": "Reflected XSS → session/cookie theft",
        "story": [
            "Penyerang mencari parameter yang nilainya direfleksikan ke HTML "
            "tanpa encoding yang benar.",
            "Marker jinak dipakai untuk memastikan refleksi benar-benar terjadi "
            "di konteks HTML, bukan sekadar muncul sebagai teks biasa.",
            "Kalau ada cookie sesi tanpa HttpOnly atau CSP yang lemah, "
            "penyerang dapat menyusun link yang menjalankan skrip di browser "
            "korban.",
            "Korban yang membuka link itu bisa kehilangan sesi, diarahkan ke "
            "halaman palsu, atau dijadikan titik awal serangan ke akun lain.",
            "Scan tidak pernah menjalankan JavaScript, mencuri cookie, atau "
            "menyimpan payload.",
        ],
        "impact": "Pengambilalihan sesi korban atau phishing di dalam origin "
                  "aplikasi yang dipercaya.",
        "confirm": [
            "Reproduksi refleksi di browser dengan akun uji, cek apakah marker "
            "muncul mentah di HTML.",
            "Periksa atribut cookie sesi (HttpOnly, Secure, SameSite) dan "
            "kebijakan CSP.",
            "Jangan pernah menguji dengan sesi pengguna nyata.",
        ],
        "tools": ["browser DevTools", "Burp Suite Repeater",
                  "nuclei (template non-intrusif)"],
    },
    "ssti": {
        "title": "Server-side template injection → server-side execution",
        "story": [
            "Penyerang menguji apakah input dievaluasi oleh template engine "
            "server-side memakai ekspresi aritmetika jinak.",
            "Hasil evaluasi yang hanya muncul setelah diproses server "
            "menandakan input masuk ke template engine.",
            "Pada kondisi nyata, penyerang dapat mencoba membaca variabel "
            "server, konfigurasi, atau menjalankan fungsi internal.",
            "Eskalasi paling berbahaya adalah eksekusi perintah di server, "
            "yang berarti seluruh aplikasi dan datanya berada di bawah kendali "
            "penyerang.",
            "Scan hanya memakai ekspresi aritmetika dan tidak menjalankan "
            "perintah apa pun.",
        ],
        "impact": "Eksekusi kode/perintah di server, kebocoran konfigurasi, dan "
                  "potensi pengambilalihan host aplikasi.",
        "confirm": [
            "Pastikan produk aritmetika hanya muncul setelah diproses server, "
            "bukan karena refleksi biasa.",
            "Identifikasi template engine dari teknologi yang terdeteksi.",
            "Uji hanya di lingkungan uji milik sendiri.",
        ],
        "tools": ["curl / browser DevTools", "Burp Suite Repeater"],
    },
    "lfi": {
        "title": "Local file inclusion → file disclosure",
        "story": [
            "Penyerang mencari parameter bernama file/path/page yang menerima "
            "nama berkas.",
            "Uji traversal jinak dilakukan untuk melihat apakah berkas sistem "
            "ikut terbaca.",
            "Jika berhasil, penyerang dapat membaca konfigurasi, kredensial "
            "database, kunci privat, atau kode sumber aplikasi.",
            "Kredensial dari file konfigurasi sering membuka jalur ke database "
            "atau layanan internal yang tidak terekspos ke internet.",
            "Scan hanya memeriksa signature berkas umum pada dua kedalaman "
            "traversal; data sensitif tidak diambil.",
        ],
        "impact": "Kebocoran file konfigurasi/kredensial dan potensi akses ke "
                  "layanan internal.",
        "confirm": [
            "Pastikan parameter benar-benar memengaruhi pemilihan berkas.",
            "Gunakan berkas uji yang tidak sensitif untuk konfirmasi.",
            "Jangan membaca atau menyimpan data pengguna.",
        ],
        "tools": ["curl / browser DevTools", "ffuf (validasi manual di scope)"],
    },
    "backdoor": {
        "title": "Web shell / backdoor → command execution",
        "story": [
            "Penyerang memindai path web shell umum yang mungkin tertinggal "
            "dari insiden atau unggahan sebelumnya.",
            "Keberadaan shell dicek dari signature source, bukan dengan "
            "mengirim command.",
            "Shell yang benar-benar aktif berarti siapa pun yang menemukannya "
            "memegang eksekusi perintah di server.",
            "Dari shell, penyerang biasanya mengakses database, menanam akses "
            "baru, dan bergerak ke host lain di jaringan internal.",
            "Scan tidak pernah mengirim parameter command ke file yang "
            "ditemukan dan tidak mengeksekusi apa pun.",
        ],
        "impact": "Eksekusi perintah di server, akses database, dan pergerakan "
                  "lateral di jaringan internal.",
        "confirm": [
            "Pastikan file benar-benar ada dan berisi kode shell, bukan "
            "halaman error atau catch-all.",
            "Jangan mengirim command; cukup verifikasi signature dan lokasi.",
            "Segera laporkan ke pemilik server untuk isolasi.",
        ],
        "tools": ["ffuf / gobuster (enumerasi path)", "curl",
                  "nuclei (template eksposur)"],
    },
    "ssrf": {
        "title": "SSRF → internal service access",
        "story": [
            "Penyerang mencari parameter berbentuk URL (url, next, callback, "
            "webhook) yang di-fetch oleh server.",
            "Probe memakai host acak berdomain .invalid untuk melihat apakah "
            "server melakukan resolusi DNS sendiri.",
            "Jika nyata, penyerang dapat mencoba menjangkau layanan internal "
            "atau metadata cloud yang tidak terbuka dari luar.",
            "Akses ke metadata cloud bisa berujung pada pencurian kredensial "
            "sementara yang memberi akses ke akun cloud.",
            "Scan tidak pernah meminta alamat internal atau endpoint metadata.",
        ],
        "impact": "Akses ke layanan internal, metadata cloud, atau kredensial "
                  "infrastruktur.",
        "confirm": [
            "Pastikan server memang melakukan fetch ke host yang dikendalikan "
            "penguji (gunakan kanal milik sendiri).",
            "Periksa allowlist egress dan segmentasi jaringan.",
            "Jangan menyentuh alamat internal atau metadata cloud.",
        ],
        "tools": ["curl / Burp Suite Collaborator (di scope sendiri)",
                  "interactsh (hanya kanal milik penguji)"],
    },
    "crlf": {
        "title": "CRLF / header injection → response splitting",
        "story": [
            "Penyerang menguji apakah nilai parameter ikut masuk ke header "
            "respons.",
            "Marker header khusus X-WW-* dipakai; keberhasilan hanya dihitung "
            "bila marker muncul sebagai nama header.",
            "Pada kondisi nyata, penyerang dapat menyisipkan header atau "
            "memecah respons untuk cache poisoning atau phishing.",
            "Cache poisoning bisa membuat pengguna lain menerima konten palsu "
            "dari domain yang mereka percaya.",
            "Scan hanya memakai marker miliknya sendiri dan tidak menyisipkan "
            "header berbahaya.",
        ],
        "impact": "Cache poisoning, phishing lewat domain tepercaya, atau "
                  "manipulasi header keamanan.",
        "confirm": [
            "Pastikan marker muncul sebagai nama header, bukan sebagai isi.",
            "Cek apakah ada cache di depan aplikasi.",
            "Uji dengan header milik sendiri, bukan header berbahaya.",
        ],
        "tools": ["Burp Suite Repeater", "curl -i"],
    },
    "exposure": {
        "title": "File/config exposure → credential discovery",
        "story": [
            "Penyerang mengenumerasi path sensitif (backup, .git, .env, admin "
            "console, file konfigurasi).",
            "Setiap path dibandingkan dengan path kontrol acak supaya server "
            "catch-all tidak dianggap temuan.",
            "File yang benar-benar terbuka dapat membocorkan kredensial, kode "
            "sumber, atau konfigurasi internal.",
            "Dari kredensial itu, penyerang dapat mencoba akses ke panel admin, "
            "database, atau repositori kode.",
            "Scan hanya melakukan GET dan tidak memakai kredensial yang "
            "ditemukan.",
        ],
        "impact": "Kebocoran kredensial, kode sumber, atau konfigurasi yang "
                  "membuka akses lebih dalam.",
        "confirm": [
            "Pastikan path mengembalikan konten nyata, bukan halaman error.",
            "Bandingkan dengan path kontrol acak pada host yang sama.",
            "Jangan memakai kredensial yang ditemukan untuk request lanjutan.",
        ],
        "tools": ["ffuf / gobuster", "curl", "nuclei (template eksposur)"],
    },
    "secrets": {
        "title": "Client-side secret exposure → credential reuse",
        "story": [
            "Penyerang membaca HTML/JS yang dikirim ke browser dan mencari "
            "string berbentuk kredensial.",
            "Kandidat divalidasi ulang (slug/nama file/placeholder/entropy) "
            "supaya nama dokumen tidak dianggap API key.",
            "Kredensial yang benar-benar live dapat dipakai ulang sesuai scope "
            "layanannya.",
            "Dampaknya bergantung pada izin kunci: dari kuota layanan sampai "
            "akses ke data pengguna atau infrastruktur.",
            "Scan tidak pernah memakai kredensial tersebut untuk request "
            "lanjutan.",
        ],
        "impact": "Penyalahgunaan kuota/layanan berbayar atau akses data sesuai "
                  "scope kredensial.",
        "confirm": [
            "Pastikan nilai bukan placeholder, slug dokumen, atau contoh.",
            "Cek tipe kredensial dan cakupan izinnya tanpa melakukan request.",
            "Laporkan ke pemilik layanan agar kunci dirotasi.",
        ],
        "tools": ["browser DevTools / View Source",
                  "TruffleHog (offline, di salinan file)",
                  "curl (hanya verifikasi eksposur)"],
    },
    "takeover": {
        "title": "Subdomain takeover → domain impersonation",
        "story": [
            "Penyerang memeriksa CNAME yang menunjuk layanan pihak ketiga yang "
            "sudah tidak aktif.",
            "Sinyal 404/claim page dari provider dikorelasikan tanpa mengklaim "
            "resource apa pun.",
            "Bila nyata, penyerang dapat mendaftarkan resource tersebut dan "
            "menyajikan konten atas nama domain target.",
            "Subdomain yang diambil alih bisa dipakai untuk phishing, mencuri "
            "cookie ber-scope domain induk, atau melewati allowlist.",
            "Scan tidak pernah mengklaim atau mendaftarkan resource.",
        ],
        "impact": "Impersonasi domain, phishing, dan potensi pencurian cookie "
                  "ber-scope domain induk.",
        "confirm": [
            "Pastikan CNAME menunjuk layanan yang tidak lagi diklaim.",
            "Cek halaman provider menampilkan status unclaimed.",
            "Jangan mendaftarkan resource; laporkan ke pemilik domain.",
        ],
        "tools": ["dig / nslookup", "curl", "subjack (validasi manual)"],
    },
    "cors": {
        "title": "CORS misconfiguration → cross-origin data read",
        "story": [
            "Penyerang menguji apakah origin arbitrer (termasuk null) mendapat "
            "izin baca lintas origin.",
            "Kombinasi ACAO/ACAC dinilai dari respons aktual, bukan asumsi.",
            "Jika nyata, halaman jahat dapat membaca data korban yang sedang "
            "login.",
            "Dengan kredensial korban, penyerang dapat mengekspor data akun "
            "tanpa pernah mencuri password.",
            "Scan hanya mengirim header Origin dan tidak mengeksekusi skrip "
            "lintas origin.",
        ],
        "impact": "Pembacaan data akun korban dari origin lain selama sesi "
                  "masih aktif.",
        "confirm": [
            "Pastikan origin yang diuji memang tidak diizinkan secara bisnis.",
            "Cek apakah respons menyertakan kredensial (ACAC true).",
            "Jangan mengeksekusi skrip lintas origin.",
        ],
        "tools": ["browser DevTools", "curl -H 'Origin: ...'"],
    },
    "access-control-bypass": {
        "title": "Access-control bypass → protected resource access",
        "story": [
            "Penyerang mencoba variasi path/header pada endpoint yang "
            "seharusnya dilindungi.",
            "Bypass hanya dicatat bila respons berbeda dari baseline 401/403 "
            "dan bisa direproduksi.",
            "Jika nyata, penyerang dapat membaca area admin atau data pengguna "
            "lain.",
            "Akses ke satu panel admin sering cukup untuk mengubah konfigurasi "
            "atau membuat akun baru.",
            "Scan hanya memakai variasi path/header read-only tanpa login.",
        ],
        "impact": "Akses ke area admin atau data pengguna lain tanpa otorisasi.",
        "confirm": [
            "Pastikan respons bypass berbeda dari baseline dan stabil.",
            "Cek apakah konten yang muncul benar-benar data terlindungi.",
            "Uji dengan akun uji, bukan akun pengguna nyata.",
        ],
        "tools": ["Burp Suite Intruder", "ffuf (path variants)", "curl"],
    },
    "headers": {
        "title": "Security header weakness → client-side attack surface",
        "story": [
            "Penyerang mencatat header keamanan yang tidak konsisten antar "
            "endpoint.",
            "Header yang hilang tidak langsung menjadi celah, tetapi "
            "mempermudah XSS, clickjacking, atau downgrade.",
            "Pada kombinasi tertentu, penyerang dapat menyusun serangan "
            "client-side yang lebih sulit dideteksi.",
            "Dampak akhirnya bergantung pada temuan lain di host yang sama.",
            "Scan hanya mengamati header pada respons yang sudah diambil.",
        ],
        "impact": "Memperbesar dampak XSS/clickjacking; bukan celah tunggal.",
        "confirm": [
            "Cek header pada endpoint HTML yang menangani sesi.",
            "Bedakan HSTS (hanya HTTPS) dari header lain.",
            "Jangan menilai dari satu endpoint saja.",
        ],
        "tools": ["browser DevTools", "curl -I", "securityheaders.com (opsional)"],
    },
    "tokens": {
        "title": "Token exposure → session/credential risk",
        "story": [
            "Penyerang mencari token yang dikirim dalam respons atau tersimpan "
            "di halaman.",
            "Klasifikasi offline memisahkan token publik dari token "
            "terautentikasi.",
            "Token terautentikasi yang bocor dapat dipakai ulang sampai masa "
            "berlakunya habis.",
            "Cookie tanpa HttpOnly memperbesar risiko pencurian lewat XSS.",
            "Scan hanya membaca dan mengklasifikasi; token tidak diverifikasi "
            "atau dipakai ulang.",
        ],
        "impact": "Pengambilalihan sesi bila token terautentikasi bocor.",
        "confirm": [
            "Pastikan token bukan token publik/anonymous.",
            "Cek masa berlaku dan scope token.",
            "Jangan memakai token untuk request lanjutan.",
        ],
        "tools": ["browser DevTools", "jwt.io (offline)", "curl (hanya baca)"],
    },
    "misconfig": {
        "title": "Konfigurasi lemah → permukaan serangan lebih luas",
        "story": [
            "Penyerang mencatat konfigurasi yang membuka informasi atau "
            "mempermudah langkah berikutnya.",
            "Konfigurasi ini jarang cukup untuk compromise langsung, tetapi "
            "sering menjadi bagian dari rantai serangan.",
            "Gabungan beberapa temuan low dapat menaikkan dampak total.",
            "Laporan yang baik menjelaskan kombinasi itu, bukan hanya satu item.",
            "Scan berhenti pada pengamatan read-only.",
        ],
        "impact": "Mempermudah eksploitasi temuan lain di host yang sama.",
        "confirm": [
            "Konfirmasi konfigurasi dari respons aktual.",
            "Cari temuan lain yang bisa digabungkan.",
            "Jangan mengubah konfigurasi.",
        ],
        "tools": ["curl -I", "browser DevTools"],
    },
}

FALLBACK = {
    "title": "Dampak lanjutan",
    "story": [
        "Penyerang mengumpulkan temuan ini bersama hasil recon lain.",
        "Temuan divalidasi ulang secara manual di dalam scope.",
        "Bila nyata, dampaknya digabungkan dengan temuan lain menjadi jalur "
        "serangan yang lebih panjang.",
        "Laporan yang lengkap menjelaskan kondisi awal, langkah verifikasi, "
        "dan dampak bisnisnya.",
        "Scan berhenti di bukti read-only dan tidak menggabungkan langkah "
        "eksploitasi.",
    ],
    "impact": "Bergantung pada temuan lain yang bisa dirangkai.",
    "confirm": [
        "Reproduksi temuan dua kali pada request terpisah.",
        "Cari temuan pendukung di host yang sama.",
        "Jangan melampaui batas read-only.",
    ],
    "tools": ["curl", "Burp Suite Repeater"],
}


def scenario_for(category: str) -> dict:
    return SCENARIOS.get((category or "").lower(), FALLBACK)


def _select(findings, limit: int = 24) -> list:
    selected = [
        finding for finding in findings
        if not finding.decoy_suspected
        and SEVERITY_ORDER.get(finding.severity, 9) <= SEVERITY_ORDER["medium"]
    ]
    selected.sort(key=lambda item: (
        SEVERITY_ORDER.get(item.severity, 9),
        item.category.lower(),
        item.host,
    ))
    return selected[:limit]


def scenario_items(findings) -> list[dict]:
    """Structured stories for Markdown and HTML renderers."""
    items = []
    for finding in _select(findings):
        scenario = scenario_for(finding.category)
        items.append({
            "title": finding.title,
            "severity": finding.severity,
            "host": finding.host,
            "url": finding.url,
            "category": finding.category,
            "verified": finding.verified,
            "reproductions": finding.reproductions,
            "stable": finding.stable,
            "scenario_title": scenario["title"],
            "story": list(scenario["story"]),
            "impact": scenario["impact"],
            "confirm": list(scenario["confirm"]),
            "tools": list(scenario["tools"]),
        })
    return items


def render_scenarios(findings) -> list[str]:
    items = scenario_items(findings)
    if not items:
        return []
    lines = [
        "## Skenario attacker (simulasi)",
        "",
        "> **" + BOUNDARY + "**",
        "",
        STORY_PREFIX,
        "",
        "| # | Temuan | Severity | Host |",
        "| --- | --- | --- | --- |",
    ]
    for index, item in enumerate(items, start=1):
        lines.append(
            f"| {index} | {item['scenario_title']} | "
            f"{item['severity'].upper()} | {item['host']} |")
    lines.append("")
    for index, item in enumerate(items, start=1):
        state = "verified" if item["verified"] else "perlu verifikasi manual"
        lines.append(f"### {index}. [{item['severity'].upper()}] "
                     f"{item['scenario_title']} — {item['host']}")
        lines.append("")
        lines.append(f"**Temuan teramati:** {item['title']} "
                     f"({state}; {item['reproductions']}× reproduksi)")
        if item["url"]:
            lines.append("")
            lines.append(f"`{item['url']}`")
        lines.append("")
        lines.append("**Cerita exploitasi (hipotetis):**")
        lines.append("")
        for step_no, step in enumerate(item["story"], start=1):
            lines.append(f"{step_no}. {step}")
        lines.append("")
        lines.append(f"**Dampak jika terbukti:** {item['impact']}")
        lines.append("")
        lines.append("**Cara konfirmasi manual di dalam scope:**")
        lines.append("")
        for step_no, step in enumerate(item["confirm"], start=1):
            lines.append(f"{step_no}. {step}")
        lines.append("")
        lines.append("**Alat verifikasi manual (bukan dijalankan oleh scan):** "
                     + ", ".join(item["tools"]))
        lines.append("")
        lines.append("**Titik henti:** scan hanya mengirim GET/HEAD dan berhenti "
                     "di bukti di atas; tidak ada langkah pada cerita ini yang "
                     "dieksekusi.")
        lines.append("")
    return lines


def render_coverage(recon: dict, stats: dict, findings) -> list[str]:
    injection = recon.get("injection") or {}
    checks = injection.get("checks") or {}
    backdoors = recon.get("backdoors") or {}
    exposure_count = sum(
        1 for finding in findings
        if finding.category.lower() in ("exposure", "backdoor")
        and not finding.decoy_suspected
    )
    rows = []
    if injection.get("enabled"):
        rows.extend([
            ("SQL injection (error/boolean)", "parameter GET",
             checks.get("sql_error", 0) + checks.get("sql_boolean", 0)),
            ("Reflected XSS", "parameter GET", checks.get("xss", 0)),
            ("SSTI", "parameter GET", checks.get("ssti", 0)),
            ("LFI / path traversal", "parameter GET", checks.get("lfi", 0)),
            ("SSRF", "parameter GET", checks.get("ssrf", 0)),
            ("CRLF / header injection", "parameter GET", checks.get("crlf", 0)),
        ])
    if backdoors.get("enabled"):
        rows.append(("Web shell / backdoor", "signature path",
                     stats.get("backdoor_findings", 0)))
    disclosure = recon.get("disclosure") or {}
    if disclosure.get("enabled"):
        pages = disclosure.get("pages_scanned", 0)
        rows.append(("Verbose error / stack trace", f"GET {pages} halaman",
                     disclosure.get("errors", 0)))
        rows.append(("Endpoint JSON tanpa autentikasi",
                     f"GET {pages} halaman",
                     disclosure.get("json", 0)))
    rows.append(("Exposure (config/backup/debug/RCE surface)", "cek path",
                 exposure_count))
    if rows:
        lines = [
            "## Cakupan deteksi",
            "",
            "| Kelas | Metode | Finding |",
            "| --- | --- | --- |",
        ]
        for name, method, count in rows:
            lines.append(f"| {name} | {method} | {count} |")
        lines.append("")
        lines.append(
            "Kelas yang butuh eksekusi perintah, upload file, atau replay "
            "kredensial tidak dijalankan; lihat bagian Batasan.")
        lines.append("")
        return lines
    return []
