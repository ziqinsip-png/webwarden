"""Self-contained HTML report with no external assets."""

from __future__ import annotations

import html
from collections import Counter

from .models import Finding, ScanResult
from .scenario import BOUNDARY as SCENARIO_BOUNDARY
from .scenario import STORY_PREFIX, scenario_items

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_LABEL = {name: name.upper() for name in SEVERITIES}
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}
CHAIN_STATUS_LABEL = {
    "observed": "OBSERVED",
    "partial": "PARTIAL",
    "blocked": "BLOCKED",
}

ID_TEXT = {
    # navigation / header
    "Summary": "Ringkasan",
    "Chains": "Rantai bukti",
    "Readiness": "Kesiapan lapor",
    "Findings": "Temuan",
    "Recon": "Recon",
    "Audit": "Audit AI",
    "webwarden report": "Laporan webwarden",
    "Authorized security assessment": "Asesmen keamanan yang diizinkan",
    "Generated": "Dibuat",
    "Scope": "Scope",
    "Authorization": "Izin",
    "operator flag (unverified)": "flag operator (belum diverifikasi)",
    "not confirmed": "belum dikonfirmasi",
    "Read-only checks": "Pemeriksaan read-only",
    "License": "Lisensi",
    "finding(s)": "temuan",
    "chain(s)": "rantai",
    # cards
    "Risk score": "Skor risiko",
    "Critical / High": "Kritis / Tinggi",
    "Medium / Low": "Sedang / Rendah",
    "Verified": "Terverifikasi",
    "Stable": "Stabil",
    "Build drift": "Build drift",
    "Missing chunks": "Chunk hilang",
    "Requests": "Request",
    # private evidence banner
    "PRIVATE — VERBATIM EVIDENCE.": "PRIVAT — BUKTI VERBATIM.",
    "The <code>evidence/</code> directory and the evidence blocks below are "
    "exact server responses. They are not truncated or redacted and may contain "
    "live passwords, API keys, cookies, tokens, and personal data. Keep this "
    "report owner-only and redact third-party secrets only if the disclosure "
    "policy requires it. The optional AI audit receives scrubbed excerpts only; "
    "the local evidence does not.":
        "Direktori <code>evidence/</code> dan blok bukti di bawah ini adalah "
        "respons server apa adanya. Tidak dipotong dan tidak disamarkan, dan "
        "bisa berisi password, API key, cookie, token, serta data pribadi yang "
        "masih aktif. Simpan laporan ini hanya untuk pemilik dan samarkan "
        "secret pihak ketiga hanya bila kebijakan pengungkapan mensyaratkannya. "
        "Audit AI opsional hanya menerima kutipan yang sudah dibersihkan; bukti "
        "lokal tidak.",
    # decoy note
    "finding(s) advertise themselves as a honeypot, decoy, canary, or test "
    "credential. They are shown for completeness but excluded from the risk "
    "score and priority ordering.":
        "temuan menandai dirinya sebagai honeypot, decoy, canary, atau "
        "kredensial uji. Ditampilkan demi kelengkapan tetapi dikeluarkan dari "
        "skor risiko dan urutan prioritas.",
    "(+{n} more)": "(+{n} lainnya)",
    "n/a": "n/a",
    # scenario section
    "Attacker scenario (simulation)": "Skenario attacker (simulasi)",
    "Observed condition": "Kondisi teramati",
    "Exploitation story (hypothetical)": "Cerita exploitasi (hipotetis)",
    "Impact if confirmed": "Dampak jika terbukti",
    "Manual confirmation inside scope": "Konfirmasi manual di dalam scope",
    "Manual verification tools (not run by this scan)":
        "Alat verifikasi manual (bukan dijalankan oleh scan ini)",
    "Stop point": "Titik henti",
    "This scan only sent GET/HEAD and stopped at the evidence above; none of "
    "the story steps were executed.":
        "Scan ini hanya mengirim GET/HEAD dan berhenti di bukti di atas; tidak "
        "ada langkah pada cerita ini yang dieksekusi.",
    "verified": "terverifikasi",
    "needs manual check": "perlu verifikasi manual",
    "reproduced": "reproduksi",
    # decoys
    "Decoy / canary signals": "Sinyal decoy / canary",
    "decoy marker": "marker decoy",
    "Decoy / canary suspected.": "Dicurigai decoy / canary.",
    "This finding is excluded from the risk score and from priority "
    "ordering. Confirm whether the condition is planted before reporting it.":
        "Temuan ini dikeluarkan dari skor risiko dan urutan prioritas. "
        "Pastikan dulu apakah kondisi ini memang ditanam sebelum melaporkannya.",
    # readiness
    "Submission readiness": "Kesiapan lapor",
    "Bucket": "Kategori",
    "Count": "Jumlah",
    "Verified critical/high/medium candidates":
        "Kandidat kritis/tinggi/sedang yang terverifikasi",
    "Informational/low items (usually not rewarded)":
        "Item info/rendah (biasanya tidak dinilai)",
    "Decoy/canary findings excluded from scoring":
        "Temuan decoy/canary yang dikeluarkan dari skor",
    "Before submitting": "Sebelum submit",
    # grouped findings
    "Grouped findings": "Temuan per kelompok",
    "Issue": "Temuan",
    "Severity": "Severity",
    "Category": "Kategori",
    "Affected hosts": "Host terdampak",
    "No findings were produced. This does not prove the target is secure; "
    "manual testing is still required.":
        "Tidak ada temuan. Ini bukan bukti target aman; pengujian manual tetap "
        "diperlukan.",
    # details / filters
    "Finding details": "Detail temuan",
    "All": "Semua",
    "Verified only": "Hanya terverifikasi",
    "Hide decoys": "Sembunyikan decoy",
    "Search findings": "Cari temuan",
    # finding block
    "Host": "Host",
    "Confidence": "Confidence",
    "yes": "ya",
    "no": "tidak",
    "Chains": "Rantai",
    "Verification": "Verifikasi",
    "Evidence SHA-256": "SHA-256 bukti",
    "Captured": "Tercatat",
    "Raw files": "File mentah",
    "not written": "tidak ditulis",
    " (TRUNCATED at the configured limit)": " (TRUNCATED di batas konfigurasi)",
    " (complete)": " (lengkap)",
    "Evidence": "Bukti",
    "CVE references": "Referensi CVE",
    "PoC (authorized scope only)": "PoC (hanya scope berizin)",
    "Remediation": "Remediasi",
    "References": "Referensi",
    "decoy suspected": "dicurigai decoy",
    "verified": "terverifikasi",
    "needs manual check": "perlu cek manual",
    "not re-checked": "belum dicek ulang",
    "stable": "stabil",
    "unstable": "tidak stabil",
    "observed": "teramati",
    # chains
    "Evidence-linked exploit chains": "Rantai exploit berbasis bukti",
    "If confirmed": "Jika terbukti",
    "Read-only proof steps": "Langkah bukti read-only",
    "Chain limitations": "Batasan rantai",
    "Open finding": "Buka finding",
    "Impact if confirmed:": "Dampak jika terbukti:",
    # probes
    "Injection and backdoor probes": "Probe injection dan backdoor",
    "Parameters": "Parameter",
    "SQL error": "SQL error",
    "SQL boolean": "SQL boolean",
    "CDN/WAF fingerprint": "Fingerprint CDN/WAF",
    # bundles
    "Bundle / build drift": "Bundle / build drift",
    "Hosts": "Host",
    "Assets": "Aset",
    "Manifests": "Manifest",
    "Drift": "Drift",
    "Missing": "Hilang",
    "Truncated": "Terpotong",
    "Library": "Library",
    "Versions observed": "Versi teramati",
    "Signal": "Sinyal",
    "Detail": "Detail",
    "Missing chunk": "Chunk hilang",
    "Control asset": "Aset kontrol",
    "Truncated asset": "Aset terpotong",
    "Captured bytes": "Byte tercatat",
    "Asset": "Aset",
    "Role": "Peran",
    "Bytes": "Byte",
    "Build hash": "Hash build",
    "Libraries": "Library",
    "Asset inventory": "Inventaris aset",
    # audit
    "AI-assisted audit": "Audit berbantuan AI",
    "Priority order": "Urutan prioritas",
    "Validation": "Validasi",
    "Why it matters": "Kenapa penting",
    "Action": "Tindakan",
    "Correlated hypotheses": "Hipotesis terkait",
    "Manual review queue": "Antrian review manual",
    "Remediation plan": "Rencana remediasi",
    "Suggested next steps": "Langkah berikutnya",
    "Audit notes": "Catatan audit",
    "Provider": "Provider",
    "unchecked": "belum dicek",
    # recon
    "Record": "Record",
    "Values": "Nilai",
    "Live HTTP hosts": "Host HTTP aktif",
    "Status": "Status",
    "Title": "Judul",
    "Server": "Server",
    "Tech": "Tech",
    "Open ports": "Port terbuka",
    "IP": "IP",
    "Port": "Port",
    "Service": "Service",
    "Security header coverage": "Cakupan security header",
    "Endpoint": "Endpoint",
    "security.txt is not present": "security.txt tidak ada",
    "Client-side exposure": "Eksposur sisi klien",
    "Kind": "Jenis",
    "Redacted value": "Nilai disamarkan",
    "Files": "File",
    "Source map": "Source map",
    "Referenced by": "Direferensikan oleh",
    "Sources": "Sumber",
    "Component versions": "Versi komponen",
    "Component": "Komponen",
    "Version": "Versi",
    "Access-control bypass checks": "Pemeriksaan bypass access-control",
    "Path": "Path",
    "Baseline": "Baseline",
    "Variants": "Varian",
    "Result": "Hasil",
    "no bypass": "tidak ada bypass",
    "No sensitive path returned HTTP 401/403.":
        "Tidak ada path sensitif yang mengembalikan HTTP 401/403.",
    "Subdomain takeover candidates": "Kandidat subdomain takeover",
    "CNAME": "CNAME",
    "Provider": "Provider",
    "candidate": "kandidat",
    "no marker": "tidak ada marker",
    "No host matched a third-party CNAME plus an unclaimed-resource page.":
        "Tidak ada host yang cocok dengan CNAME pihak ketiga plus halaman "
        "resource unclaimed.",
    # warnings / limitations / footer
    "Warnings": "Peringatan",
    "Limitations": "Batasan",
    "Generated by webwarden. Use only within an authorized scope.":
        "Dibuat oleh webwarden. Gunakan hanya di dalam scope yang diizinkan.",
    "Theme: Auto": "Tema: Auto",
    # long notes
    "A chain is assembled only from findings this scan already observed. Each "
    "link points at a specific finding and inherits its reproduction status, so "
    "a chain cannot introduce a condition that was not seen. No chain was "
    "executed: no session was hijacked, no credential replayed, and no request "
    "beyond read-only GET/HEAD was sent.":
        "Rantai hanya disusun dari temuan yang sudah diamati scan ini. Setiap "
        "mata rantai menunjuk finding tertentu dan mewarisi status "
        "reproduksinya, jadi rantai tidak bisa memunculkan kondisi yang tidak "
        "terlihat. Tidak ada rantai yang dieksekusi: tidak ada sesi dibajak, "
        "tidak ada kredensial di-replay, dan tidak ada request di luar "
        "GET/HEAD read-only.",
    "every link reproduced on independent requests":
        "setiap mata rantai tereproduksi pada request terpisah",
    "at least one link needs manual confirmation (severity capped at medium)":
        "minimal satu mata rantai perlu konfirmasi manual (severity maksimal "
        "medium)",
    "decoy marker or the next step would leave the read-only boundary":
        "marker decoy atau langkah berikutnya keluar dari batas read-only",
    "No chain matched the observed findings. That does not mean no multi-step "
    "issue exists; the automated evidence simply did not connect any "
    "conditions.":
        "Tidak ada rantai yang cocok dengan temuan. Ini bukan berarti tidak ada "
        "masalah multi-langkah; bukti otomatis hanya belum menghubungkan "
        "kondisi apa pun.",
    "A response advertises itself as a honeypot, decoy, or test artifact.":
        "Respons menandai dirinya sebagai honeypot, decoy, atau artefak uji.",
    "Injection probes append a benign signature, arithmetic expression, or "
    "traversal to one query parameter over GET only; nothing is extracted, "
    "written, or authenticated. A candidate is reported only when the signal "
    "is absent from the untouched baseline and reproduces. Backdoor checks "
    "request a fixed list of common web shell paths and never submit a "
    "command.":
        "Probe injection menambahkan signature jinak, ekspresi aritmetika, "
        "atau traversal ke satu parameter query lewat GET saja; tidak ada data "
        "yang diekstrak, ditulis, atau diautentikasi. Kandidat hanya dilaporkan "
        "bila sinyalnya tidak ada di baseline dan tereproduksi. Pemeriksaan "
        "backdoor meminta daftar path web shell umum dan tidak pernah mengirim "
        "command.",
    "CDN/WAF fingerprint": "Fingerprint CDN/WAF",
    "Passive header match, not a vulnerability.":
        "Cocokkan header pasif, bukan kerentanan.",
    "Served HTML was compared read-only with the build artifacts it "
    "references: hashed chunks, framework manifests, service-worker precache, "
    "and generator/\"?ver=\" values. Drift between what the page references and "
    "what the server serves usually means a stale deployment, where the server "
    "may be patched while an older client bundle is still cached. Drift is a "
    "deployment signal, not a vulnerability.":
        "HTML yang disajikan dibandingkan secara read-only dengan artefak build "
        "yang direferensikannya: chunk ber-hash, manifest framework, precache "
        "service worker, dan nilai generator/\"?ver=\". Drift antara yang "
        "direferensikan halaman dan yang disajikan server biasanya berarti "
        "deployment basi, di mana server mungkin sudah dipatch sementara bundle "
        "client lama masih di-cache. Drift adalah sinyal deployment, bukan "
        "kerentanan.",
    "No bundle artifacts were reachable within the read-only budget.":
        "Tidak ada artefak bundle yang bisa dijangkau dalam budget read-only.",
    "The server declared more bytes than the read cap for these assets, so "
    "version and secret analysis covered only the captured prefix.":
        "Server menyatakan byte lebih banyak dari batas baca untuk aset ini, "
        "jadi analisis versi dan secret hanya mencakup prefix yang tercatat.",
    "Version strings are observations only. A distributor backport can make an "
    "old-looking version patched, and a stale string can hide a newer runtime.":
        "String versi hanya observasi. Backport distributor bisa membuat versi "
        "yang terlihat lama sebenarnya sudah dipatch, dan string basi bisa "
        "menyembunyikan runtime yang lebih baru.",
    "Guidance only. Programs reject out-of-scope, duplicate, purely "
    "informational, or impact-free reports.":
        "Hanya panduan. Program menolak laporan di luar scope, duplikat, murni "
        "informasional, atau tanpa dampak.",
    "Confirm every affected host is explicitly in scope.":
        "Pastikan setiap host terdampak tercantum eksplisit di scope.",
    "Confirm the vulnerability class is not excluded by the program.":
        "Pastikan kelas kerentanan tidak dikecualikan program.",
    "Attach the reproduction command, raw evidence, and a concrete impact "
    "statement.":
        "Lampirkan perintah reproduksi, bukti mentah, dan pernyataan dampak "
        "yang konkret.",
    "Treat tokens and secrets as inert evidence: do not authenticate with "
    "harvested credentials; ask for a sanctioned test token if needed.":
        "Perlakukan token dan secret sebagai bukti pasif: jangan autentikasi "
        "memakai kredensial hasil temuan; minta token uji resmi bila perlu.",
    "Check prior disclosures for duplicates.":
        "Cek pengungkapan sebelumnya untuk duplikat.",
    "Submit informational-only items as a note, not a vulnerability report.":
        "Kirim item informasional sebagai catatan, bukan laporan kerentanan.",
    "Automated checks are read-only (GET/HEAD). Items marked needs manual "
    "verification must be confirmed before reporting.":
        "Pemeriksaan otomatis bersifat read-only (GET/HEAD). Item bertanda "
        "perlu verifikasi manual harus dikonfirmasi sebelum dilaporkan.",
    "AI-assisted audit re-ranks observed findings only. It does not prove "
    "exploitability and must not be treated as an independent scanner.":
        "Audit berbantuan AI hanya mengurutkan ulang temuan yang teramati. Ia "
        "tidak membuktikan exploitability dan tidak boleh dianggap scanner "
        "independen.",
    "CVE candidates are version/CPE matches; confirm the exact build and "
    "backports.":
        "Kandidat CVE adalah kecocokan versi/CPE; konfirmasi build dan backport "
        "yang tepat.",
    "Evidence bodies are stored verbatim and unredacted up to --evidence-bytes "
    "(default 5 MiB, ceiling 64 MiB). A finding states when its capture hit "
    "that limit; poc.sh can retrieve the complete response.":
        "Body bukti disimpan verbatim dan tanpa redaksi sampai --evidence-bytes "
        "(default 5 MiB, batas atas 64 MiB). Finding mencantumkan bila capture "
        "mencapai batas itu; poc.sh bisa mengambil respons lengkap.",
    "Evidence-linked chains connect only conditions this scan observed. "
    "Observed means every link reproduced on independent requests; partial "
    "means at least one link needs manual confirmation; blocked means a link "
    "carries a decoy marker or the chain needs an action outside the read-only "
    "boundary. No chain was executed: no session was hijacked, no credential "
    "replayed, and no resource claimed.":
        "Rantai berbasis bukti hanya menghubungkan kondisi yang diamati scan "
        "ini. Observed berarti setiap mata rantai tereproduksi pada request "
        "terpisah; partial berarti minimal satu mata rantai perlu konfirmasi "
        "manual; blocked berarti ada marker decoy atau rantai membutuhkan "
        "tindakan di luar batas read-only. Tidak ada rantai yang dieksekusi: "
        "tidak ada sesi dibajak, kredensial di-replay, atau resource diklaim.",
    "Decoy/canary markers are detected from response text. A match warns that "
    "a finding may be intentional, not proof; decoy findings are excluded from "
    "the risk score and priority ordering.":
        "Marker decoy/canary dideteksi dari teks respons. Kecocokan hanya "
        "memperingatkan bahwa temuan mungkin disengaja, bukan bukti; temuan "
        "decoy dikeluarkan dari skor risiko dan urutan prioritas.",
    "Bundle/build drift compares served HTML with served artifacts. Drift is a "
    "deployment-consistency signal, not evidence of an exploitable condition, "
    "and version strings can be stale or backported.":
        "Bundle/build drift membandingkan HTML yang disajikan dengan artefak "
        "yang disajikan. Drift adalah sinyal konsistensi deployment, bukan bukti "
        "kondisi yang bisa dieksploitasi, dan string versi bisa basi atau "
        "di-backport.",
    "A negative bypass, chain, or takeover result does not prove that no issue "
    "exists.":
        "Hasil negatif pada bypass, rantai, atau takeover tidak membuktikan "
        "tidak ada masalah.",
    "Client-side secret matches are pattern-based candidates, never validated "
    "or replayed; report text is redacted and raw responses stay in the "
    "private evidence directory.":
        "Kecocokan secret sisi klien adalah kandidat berbasis pola, tidak "
        "pernah divalidasi atau di-replay; teks laporan disamarkan dan respons "
        "mentah tetap di direktori bukti privat.",
    "Credential-like URL parameters are flagged from crawl output without "
    "being requested.":
        "Parameter URL mirip kredensial ditandai dari output crawl tanpa "
        "diminta.",
    "No login attempts, brute force, writes, or persistence actions are "
    "performed.":
        "Tidak ada percobaan login, brute force, penulisan, atau aksi "
        "persistence yang dilakukan.",
    "Presence per endpoint; HSTS only applies to HTTPS responses.":
        "Kehadiran per endpoint; HSTS hanya berlaku untuk respons HTTPS.",
    "Secret values are redacted here; raw responses stay in the private "
    "evidence directory.":
        "Nilai secret disamarkan di sini; respons mentah tetap di direktori "
        "bukti privat.",
    "No sensitive path returned HTTP 401/403.":
        "Tidak ada path sensitif yang mengembalikan HTTP 401/403.",
    "No host matched a third-party CNAME plus an unclaimed-resource page.":
        "Tidak ada host yang cocok dengan CNAME pihak ketiga plus halaman "
        "resource unclaimed.",
    "No multipart file input was found on the target page.":
        "Tidak ditemukan input file multipart di halaman target.",
    "This is a header-only observation, not a vulnerability claim, and no "
    "fault or memory probe was sent.":
        "Ini observasi header saja, bukan klaim kerentanan, dan tidak ada probe "
        "fault atau memori yang dikirim.",
    # recon detail labels
    "Contact": "Kontak",
    "Expires": "Kedaluwarsa",
    "valid": "valid",
    "(expired)": "(kedaluwarsa)",
    "Files scanned": "File dipindai",
    "secret hits": "hit secret",
    "source maps": "source map",
    "credential-like URL parameters": "parameter URL mirip kredensial",
    "robots.txt path probing": "probe path robots.txt",
    "enabled": "aktif",
    "not requested": "tidak diminta",
    "Referrer": "Referrer",
    "Permissions": "Permissions",
    "BYPASS via": "BYPASS lewat",
    "Submission-ready items": "Item siap submit",
    "Findings grouped by issue": "Temuan dikelompokkan per isu",
}


def _lang(lang: str | None) -> str:
    return "id" if (lang or "en").lower().startswith("id") else "en"


def _tr(lang: str | None, text: str) -> str:
    if _lang(lang) == "id":
        return ID_TEXT.get(text, text)
    return text



def _e(value: object) -> str:
    return html.escape(str(value if value not in (None, "") else "-"), quote=True)


def _badge(severity: str) -> str:
    name = severity.lower() if severity.lower() in SEVERITY_ORDER else "info"
    return f'<span class="badge badge-{name}">{SEVERITY_LABEL[name]}</span>'


def _pill(status: str) -> str:
    name = status if status in CHAIN_STATUS_LABEL else "partial"
    return (
        f'<span class="pill st-{name}">{CHAIN_STATUS_LABEL[name]}</span>'
    )


def _grouped(findings: list[Finding]) -> list[tuple[str, str, str, list[Finding]]]:
    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for finding in findings:
        groups.setdefault(
            (finding.title, finding.severity, finding.category), []
        ).append(finding)
    return sorted(
        (
            (title, severity, category, items)
            for (title, severity, category), items in groups.items()
        ),
        key=lambda row: (
            SEVERITY_ORDER.get(row[1], 9),
            -len(row[3]),
            row[0].lower(),
        ),
    )


def _validation_pills(finding: Finding, lang: str = "en") -> list[str]:
    pills = []
    if finding.decoy_suspected:
        pills.append('<span class="vpill bad">'
                     + _tr(lang, "decoy suspected") + '</span>')
    if finding.verified:
        pills.append('<span class="vpill ok">'
                     + _tr(lang, "verified") + '</span>')
    else:
        pills.append('<span class="vpill warn">'
                     + _tr(lang, "needs manual check") + '</span>')
    if finding.reproductions >= 2:
        pills.append(
            f'<span class="vpill ok">{finding.reproductions}&times; '
            f'{_tr(lang, "reproduced")}</span>'
        )
    elif finding.reproductions == 1:
        pills.append('<span class="vpill warn">1&times; '
                     + _tr(lang, "observed") + '</span>')
    else:
        pills.append('<span class="vpill">'
                     + _tr(lang, "not re-checked") + '</span>')
    if finding.stable is True:
        pills.append('<span class="vpill ok">'
                     + _tr(lang, "stable") + '</span>')
    elif finding.stable is False:
        pills.append('<span class="vpill bad">'
                     + _tr(lang, "unstable") + '</span>')
    return pills


def _finding_block(
    index: int,
    finding: Finding,
    chain_lookup: dict[str, list[tuple[str, str]]] | None = None,
    lang: str = "en",
) -> str:
    severity = finding.severity.lower()
    details = []
    details.append(
        f'<div class="meta">'
        f'<span><b>{_tr(lang, "Host")}</b> {_e(finding.host)}</span>'
        f'<span><b>{_tr(lang, "Category")}</b> {_e(finding.category)}</span>'
        f'<span><b>{_tr(lang, "Confidence")}</b> {_e(finding.confidence)}</span>'
        f'<span><b>{_tr(lang, "Verified")}</b> '
        f'{_tr(lang, "yes" if finding.verified else "no")}</span>'
        f'</div>'
    )
    details.append(f'<p class="url">{_e(finding.url)}</p>')
    details.append(
        '<div class="vpills">' + "".join(_validation_pills(finding, lang))
        + '</div>'
    )
    if finding.decoy_suspected:
        reason = str(finding.decoy_reason or "").strip()
        if reason and reason[-1] not in ".!?":
            reason += "."
        details.append(
            '<div class="decoy"><div><b>'
            + _tr(lang, "Decoy / canary suspected.") + '</b> '
            f'{_e(reason or "A response advertises itself as a honeypot, decoy, or test artifact.")} '
            + _tr(lang, "This finding is excluded from the risk score and from "
                        "priority ordering. Confirm whether the condition is "
                        "planted before reporting it.")
            + '</div></div>'
        )
    chain_links = (chain_lookup or {}).get(
        f"{(finding.title or '').lower()}|{finding.host.lower()}", []
    )
    chain_ids = list(finding.chain_ids)
    if chain_links:
        chips = " ".join(
            f'<a class="chainchip" href="#chain-{_e(chain_id)}">'
            f'{_e(chain_id)} · {_e(status)}</a>'
            for chain_id, status in chain_links
        )
        details.append(
            f'<div class="chainrefs"><b>{_tr(lang, "Chains")}</b> {chips}</div>')
    elif chain_ids:
        details.append(
            f'<div class="chainrefs"><b>{_tr(lang, "Chains")}</b> '
            + " ".join(
                f'<a class="chainchip" href="#chain-{_e(chain_id)}">{_e(chain_id)}</a>'
                for chain_id in chain_ids
            )
            + "</div>"
        )
    details.append(f'<p>{_e(finding.description)}</p>')
    if finding.verification:
        details.append(
            f'<p class="note"><b>{_tr(lang, "Verification")}:</b> '
            f'{_e(finding.verification)}</p>'
        )
    if finding.evidence_sha256:
        truncated = _tr(lang, " (TRUNCATED at the configured limit)") \
            if finding.evidence_truncated else _tr(lang, " (complete)")
        raw_files = ", ".join(finding.evidence_files) or _tr(
            lang, "not written")
        details.append(
            f'<p class="note"><b>{_tr(lang, "Evidence SHA-256")}:</b> '
            f'<code>{_e(finding.evidence_sha256)}</code><br>'
            f'<b>{_tr(lang, "Captured")}:</b> '
            f'{_e(finding.evidence_bytes)} bytes{truncated}<br>'
            f'<b>{_tr(lang, "Raw files")}:</b> <code>{_e(raw_files)}</code></p>'
        )
    if finding.evidence:
        details.append(
            f'<h4>{_tr(lang, "Evidence")}</h4><pre>'
            + _e(finding.evidence)
            + '</pre>'
        )
    if finding.cves:
        rows = []
        for cve in finding.cves:
            rows.append(
                f'<li><code>{_e(cve.id)}</code> — {_e(cve.status)}; '
                f'source: {_e(cve.source)}'
                + (f'; CVSS {_e(cve.score)}' if cve.score is not None else '')
                + '</li>'
            )
        details.append(f'<h4>{_tr(lang, "CVE references")}</h4><ul>'
                       + ''.join(rows) + '</ul>')
    if finding.poc:
        details.append(
            f'<h4>{_tr(lang, "PoC (authorized scope only)")}</h4><pre>'
            + _e("\n".join(finding.poc))
            + '</pre>'
        )
    if finding.remediation:
        details.append(
            f'<p class="remediation"><b>{_tr(lang, "Remediation")}:</b> '
            f'{_e(finding.remediation)}</p>'
        )
    if finding.references:
        details.append(
            f'<h4>{_tr(lang, "References")}</h4><ul>'
            + ''.join(f'<li>{_e(ref)}</li>' for ref in finding.references)
            + '</ul>'
        )
    return (
        f'<details class="finding" id="finding-{index}" '
        f'data-severity="{_e(severity)}" '
        f'data-verified="{"1" if finding.verified else "0"}" '
        f'data-decoy="{"1" if finding.decoy_suspected else "0"}" '
        f'data-stable="{_e("stable" if finding.stable is True else ("unstable" if finding.stable is False else "unknown"))}" '
        f'data-search="{_e((finding.title + " " + finding.host + " " + finding.url + " " + " ".join(finding.chain_ids)).lower())}">'
        f'<summary><span class="idx">{index}</span> {_badge(severity)} '
        f'<span class="title">{_e(finding.title)}</span>'
        f'<span class="host">{_e(finding.host)}</span></summary>'
        f'<div class="finding-body">{"".join(details)}</div>'
        f'</details>'
    )


def _chains_section(chains: dict, findings: list[Finding],
                    lang: str = "en") -> str:
    if not chains.get("enabled"):
        return ""
    items = chains.get("items") or []
    parts = [
        '<section id="chains"><h2>'
        + _tr(lang, "Evidence-linked exploit chains") + '</h2>',
        '<p class="note">'
        + _tr(lang, "A chain is assembled only from findings this scan "
                    "already observed. Each link points at a specific finding "
                    "and inherits its reproduction status, so a chain cannot "
                    "introduce a condition that was not seen. No chain was "
                    "executed: no session was hijacked, no credential "
                    "replayed, and no request beyond read-only GET/HEAD was "
                    "sent.")
        + '</p>',
        '<div class="legend">'
        '<div class="legend-row"><span class="pill st-observed">OBSERVED</span>'
        '<span>' + _tr(lang, "every link reproduced on independent requests")
        + '</span></div>'
        '<div class="legend-row"><span class="pill st-partial">PARTIAL</span>'
        '<span>' + _tr(lang, "at least one link needs manual confirmation "
                             "(severity capped at medium)") + '</span></div>'
        '<div class="legend-row"><span class="pill st-blocked">BLOCKED</span>'
        '<span>' + _tr(lang, "decoy marker or the next step would leave the "
                             "read-only boundary") + '</span></div>'
        '</div>',
    ]
    if not items:
        parts.append(
            '<p class="empty">'
            + _tr(lang, "No chain matched the observed findings. That does "
                        "not mean no multi-step issue exists; the automated "
                        "evidence simply did not connect any conditions.")
            + '</p></section>'
        )
        return "".join(parts)
    for chain in items:
        status = str(chain.get("status") or "partial")
        status = status if status in CHAIN_STATUS_LABEL else "partial"
        chain_id = str(chain.get("id") or "")
        links = chain.get("links") or []
        parts.append(
            f'<article class="chain-card st-{status}" id="chain-{_e(chain_id)}">'
            '<div class="chain-top">'
            f'<span class="chain-id">{_e(chain_id)}</span>'
            f'{_pill(status)}'
            f'{_badge(str(chain.get("severity") or "info"))}'
            '</div>'
            f'<h3 class="chain-title">{_e(chain.get("title"))}</h3>'
            f'<p>{_e(chain.get("summary"))}</p>'
        )
        if chain.get("impact"):
            parts.append(
                f'<p class="impact"><b>{_tr(lang, "Impact if confirmed:")}</b> '
                f'{_e(chain.get("impact"))}</p>'
            )
        if links:
            parts.append('<div class="flow">')
            for position, link in enumerate(links, start=1):
                link_status = str(link.get("status") or "partial")
                link_status = (
                    link_status if link_status in CHAIN_STATUS_LABEL
                    else "partial"
                )
                anchor = ""
                for index, finding in enumerate(findings, start=1):
                    if finding.title == link.get("title") \
                            and finding.host == link.get("host"):
                        anchor = (
                            f'<a class="node-link" href="#finding-{index}">'
                            + _tr(lang, "Open finding") + ' &rarr;</a>'
                        )
                        break
                reproduced = link.get("reproductions") or 0
                if reproduced >= 2:
                    repro = f"{reproduced}&times; {_tr(lang, 'reproduced')}"
                elif reproduced == 1:
                    repro = "1&times; " + _tr(lang, "observed")
                else:
                    repro = _tr(lang, "not re-checked")
                decoy = (
                    '<span class="vpill bad">'
                    + _tr(lang, "decoy marker") + '</span>'
                    if link.get("decoy") else ""
                )
                parts.append(
                    f'<div class="node st-{link_status}">'
                    f'<span class="node-num">{position}</span>'
                    '<div class="node-head">'
                    f'<span class="node-title">{_e(link.get("title"))}</span>'
                    f'{_pill(link_status)}{decoy}</div>'
                    '<div class="node-meta">'
                    f'{_e(link.get("host"))} · role: {_e(link.get("role"))} · '
                    f'{repro}</div>'
                    f'<p>{_e(link.get("evidence"))}</p>'
                    f'{anchor}'
                    '</div>'
                )
            parts.append('</div>')
        proof = chain.get("proof") or []
        if proof:
            parts.append('<h4>' + _tr(lang, "Read-only proof steps")
                         + '</h4><ol class="proof">')
            for step in proof:
                parts.append(f'<li>{_e(step)}</li>')
            parts.append('</ol>')
        if chain.get("limitations"):
            parts.append(
                f'<p class="note"><b>{_tr(lang, "Chain limitations")}:</b> '
                f'{_e(chain.get("limitations"))}</p>'
            )
        parts.append('</article>')
    if chains.get("note"):
        parts.append(f'<p class="note">{_e(chains.get("note"))}</p>')
    parts.append('</section>')
    return "".join(parts)


def _scenarios_section(findings: list[Finding], lang: str = "en") -> str:
    if _lang(lang) != "id":
        return ""
    items = scenario_items(findings)
    if not items:
        return ""
    parts = [
        '<section id="scenarios"><h2>Skenario attacker (simulasi)</h2>',
        f'<p class="note"><b>{_e(SCENARIO_BOUNDARY)}</b></p>',
        f'<p class="note">{_e(STORY_PREFIX)}</p>',
    ]
    for index, item in enumerate(items, start=1):
        state = "terverifikasi" if item["verified"] else "perlu verifikasi manual"
        parts.append(
            '<article class="chain-card">'
            f'<div class="chain-top"><span class="chain-id">#{index}</span>'
            f'{_badge(item["severity"])}</div>'
            f'<h3 class="chain-title">{_e(item["scenario_title"])} — '
            f'{_e(item["host"])}</h3>'
            f'<p><b>{_e(item["title"])}</b> '
            f'<span class="muted">({_e(state)}; '
            f'{_e(item["reproductions"])}&times; reproduksi)</span></p>'
        )
        if item["url"]:
            parts.append(f'<p class="url">{_e(item["url"])}</p>')
        parts.append(
            '<h4>Cerita exploitasi (hipotetis)</h4><ol class="proof">'
            + "".join(f'<li>{_e(step)}</li>' for step in item["story"])
            + '</ol>'
        )
        parts.append(
            f'<p class="impact"><b>Dampak jika terbukti:</b> '
            f'{_e(item["impact"])}</p>'
        )
        parts.append(
            '<h4>Konfirmasi manual di dalam scope</h4><ol class="plan">'
            + "".join(f'<li>{_e(step)}</li>' for step in item["confirm"])
            + '</ol>'
        )
        parts.append(
            '<p class="note"><b>Alat verifikasi manual (bukan dijalankan oleh '
            'scan ini):</b> ' + _e(", ".join(item["tools"])) + '</p>'
        )
        parts.append(
            '<p class="note"><b>Titik henti:</b> scan hanya mengirim GET/HEAD '
            'dan berhenti di bukti di atas; tidak ada langkah pada cerita ini '
            'yang dieksekusi.</p></article>'
        )
    parts.append('</section>')
    return "".join(parts)


def _probes_section(recon: dict, lang: str = "en") -> str:
    injection = recon.get("injection") or {}
    backdoors = recon.get("backdoors") or {}
    if not injection.get("enabled") and not backdoors.get("enabled"):
        return ""
    parts = [
        '<h3>' + _tr(lang, "Injection and backdoor probes") + '</h3>',
        '<p class="note">'
        + _tr(lang, "Injection probes append a benign signature, arithmetic "
                    "expression, or traversal to one query parameter over GET "
                    "only; nothing is extracted, written, or authenticated. A "
                    "candidate is reported only when the signal is absent from "
                    "the untouched baseline and reproduces. Backdoor checks "
                    "request a fixed list of common web shell paths and never "
                    "submit a command.")
        + '</p>',
    ]
    if injection.get("enabled"):
        checks = injection.get("checks") or {}
        parts.append(
            '<div class="mini-cards">'
            f'<div class="mini"><span>{_tr(lang, "Parameters")}</span>'
            f'<b>{_e(injection.get("parameters", 0))}</b></div>'
            f'<div class="mini"><span>{_tr(lang, "SQL error")}</span><b>{_e(checks.get("sql_error", 0))}</b></div>'
            f'<div class="mini"><span>{_tr(lang, "SQL boolean")}</span><b>{_e(checks.get("sql_boolean", 0))}</b></div>'
            f'<div class="mini"><span>SSTI</span><b>{_e(checks.get("ssti", 0))}</b></div>'
            f'<div class="mini"><span>XSS</span><b>{_e(checks.get("xss", 0))}</b></div>'
            f'<div class="mini"><span>LFI</span><b>{_e(checks.get("lfi", 0))}</b></div>'
            f'<div class="mini"><span>SSRF</span><b>{_e(checks.get("ssrf", 0))}</b></div>'
            f'<div class="mini"><span>CRLF</span><b>{_e(checks.get("crlf", 0))}</b></div>'
            '</div>'
        )
    if backdoors.get("enabled"):
        parts.append(
            '<p class="note">Path web shell yang diminta: '
            f'<b>{_e(backdoors.get("paths_tested", 0))}</b> pada '
            f'<b>{_e(backdoors.get("hosts", 0))}</b> host; terjangkau: '
            f'<b>{_e(backdoors.get("findings", 0))}</b>.</p>'
        )
    waf = recon.get("waf") or {}
    providers = waf.get("providers") or []
    if providers:
        listed = ", ".join(
            f'{_e(item.get("provider"))} ({_e(item.get("evidence"))})'
            for item in providers[:3]
        )
        parts.append(
            f'<p class="note">{_tr(lang, "CDN/WAF fingerprint")}: <b>'
            + listed + '</b>. '
            + _tr(lang, "Passive header match, not a vulnerability.")
            + '</p>'
        )
    for warning in (injection.get("warnings") or []) \
            + (backdoors.get("warnings") or []):
        parts.append(f'<p class="note warn">{_e(warning)}</p>')
    return "".join(parts)


def _bundles_section(bundles: dict, lang: str = "en") -> str:
    if not bundles.get("enabled"):
        return ""
    hosts = bundles.get("hosts") or []
    parts = [
        '<h3>' + _tr(lang, "Bundle / build drift") + '</h3>',
        '<p class="note">'
        + _tr(lang, "Served HTML was compared read-only with the build "
                    "artifacts it references: hashed chunks, framework "
                    "manifests, service-worker precache, and generator/"
                    "\"?ver=\" values. Drift between what the page references "
                    "and what the server serves usually means a stale "
                    "deployment, where the server may be patched while an "
                    "older client bundle is still cached. Drift is a "
                    "deployment signal, not a vulnerability.")
        + '</p>',
        '<div class="mini-cards">',
        f'<div class="mini"><span>{_tr(lang, "Hosts")}</span><b>{_e(bundles.get("hosts_checked", 0))}</b></div>',
        f'<div class="mini"><span>{_tr(lang, "Assets")}</span><b>{_e(bundles.get("assets_fetched", 0))}</b></div>',
        f'<div class="mini"><span>{_tr(lang, "Manifests")}</span><b>{_e(bundles.get("manifests", 0))}</b></div>',
        f'<div class="mini"><span>{_tr(lang, "Drift")}</span><b>{_e(bundles.get("drift", 0))}</b></div>',
        f'<div class="mini"><span>{_tr(lang, "Missing")}</span><b>{_e(bundles.get("missing_chunks", 0))}</b></div>',
        f'<div class="mini"><span>{_tr(lang, "Truncated")}</span><b>{_e(bundles.get("truncated_assets", 0))}</b></div>',
        '</div>',
    ]
    if not hosts:
        parts.append(
            '<p class="empty">'
            + _tr(lang, "No bundle artifacts were reachable within the "
                        "read-only budget.")
            + '</p>'
        )
        return "".join(parts)
    for host in hosts:
        frameworks = host.get("frameworks") or []
        build_ids = host.get("build_ids") or []
        assets = host.get("assets") or []
        drift = host.get("drift") or []
        missing = host.get("missing") or []
        tags = "".join(
            f'<span class="tag">{_e(name)}</span>' for name in frameworks
        )
        if build_ids:
            tags += "".join(
                f'<span class="tag alt">build {_e(value)}</span>'
                for value in build_ids[:4]
            )
        if not tags:
            tags = '<span class="muted">tanpa signature framework</span>'
        parts.append(
            '<div class="bhost">'
            f'<div class="bhead"><h4>{_e(host.get("host"))}</h4>'
            f'<span class="url">{_e(host.get("url"))}</span></div>'
            f'<div class="tags">{tags}</div>'
            f'<p class="note">{len(assets)} aset diambil · {len(drift)} '
            f'sinyal drift · {len(missing)} chunk hilang</p>'
        )
        if drift:
            parts.append(
                '<div class="table-wrap"><table><thead><tr>'
                f'<th>{_tr(lang, "Signal")}</th>'
                f'<th>{_tr(lang, "Detail")}</th></tr></thead><tbody>'
            )
            for entry in drift[:20]:
                signal = entry.get("type") or entry.get("signal") or "drift"
                if entry.get("logical_name"):
                    detail = (
                        f'{entry["logical_name"]}: page '
                        f'{", ".join(entry.get("page_hashes") or [])} vs '
                        f'manifest {", ".join(entry.get("manifest_hashes") or [])}'
                    )
                elif entry.get("ids"):
                    detail = "build IDs: " + ", ".join(entry["ids"])
                elif entry.get("generator"):
                    detail = (
                        f'generator {entry["generator"]} vs assets '
                        f'{", ".join(entry.get("asset_versions") or [])}'
                    )
                elif entry.get("library"):
                    detail = (
                        f'{entry["library"]} vs ?ver='
                        f'{entry.get("asset_version")}'
                    )
                else:
                    detail = str(entry)[:200]
                parts.append(
                    f'<tr><td>{_e(signal)}</td><td>{_e(detail)}</td></tr>'
                )
            parts.append('</tbody></table></div>')
        if missing:
            parts.append(
                '<div class="table-wrap"><table><thead><tr>'
                f'<th>{_tr(lang, "Missing chunk")}</th><th>HTTP</th>'
                f'<th>{_tr(lang, "Control asset")}</th>'
                '</tr></thead><tbody>'
            )
            for entry in missing[:10]:
                parts.append(
                    f'<tr><td class="url">{_e(entry.get("url"))}</td>'
                    f'<td>{_e(entry.get("status"))}</td>'
                    f'<td class="url">{_e(entry.get("control"))} '
                    f'(HTTP {_e(entry.get("control_status"))})</td></tr>'
                )
            parts.append('</tbody></table></div>')
        truncated = host.get("truncated") or []
        if truncated:
            rows = "".join(
                f'<tr><td class="url">{_e(entry.get("url"))}</td>'
                f'<td>{_e(entry.get("captured_bytes"))}</td>'
                f'<td>{_e(entry.get("declared_bytes"))}</td></tr>'
                for entry in truncated[:10]
            )
            parts.append(
                '<p class="note warn">'
                + _tr(lang, "The server declared more bytes than the read cap "
                            "for these assets, so version and secret analysis "
                            "covered only the captured prefix.")
                + '</p>'
                '<div class="table-wrap"><table><thead><tr>'
                f'<th>{_tr(lang, "Truncated asset")}</th>'
                f'<th>{_tr(lang, "Captured bytes")}</th>'
                '<th>Content-Length</th></tr></thead><tbody>'
                f'{rows}</tbody></table></div>'
            )
        if assets:
            parts.append(
                '<details class="asset-list"><summary>'
                + _tr(lang, "Asset inventory")
                + f' ({len(assets)})</summary><div class="table-wrap"><table>'
                '<thead><tr>'
                f'<th>{_tr(lang, "Asset")}</th><th>{_tr(lang, "Role")}</th>'
                f'<th>HTTP</th><th>{_tr(lang, "Bytes")}</th>'
                f'<th>{_tr(lang, "Build hash")}</th>'
                f'<th>{_tr(lang, "Libraries")}</th>'
                '</tr></thead><tbody>'
            )
            for asset in assets[:30]:
                libraries = ", ".join(
                    f'{name} {", ".join(versions)}'
                    for name, versions in (asset.get("libraries") or {}).items()
                )
                digest = str(asset.get("sha256") or "")[:16]
                bytes_cell = str(asset.get("bytes"))
                if asset.get("truncated"):
                    declared = asset.get("content_length")
                    bytes_cell += (
                        f" (truncated of {declared})" if declared
                        else " (truncated)")
                parts.append(
                    f'<tr><td class="url">{_e(asset.get("url"))}</td>'
                    f'<td>{_e(asset.get("role"))}</td>'
                    f'<td>{_e(asset.get("status"))}</td>'
                    f'<td>{_e(bytes_cell)}</td>'
                    f'<td><code>{_e(asset.get("build_hash") or digest)}</code></td>'
                    f'<td>{_e(libraries)}</td></tr>'
                )
            parts.append('</tbody></table></div></details>')
        parts.append('</div>')
    libraries = bundles.get("libraries") or {}
    if libraries:
        parts.append(
            f'<h4>{_tr(lang, "Libraries")}</h4><div class="table-wrap">'
            '<table><thead><tr>'
            f'<th>{_tr(lang, "Library")}</th>'
            f'<th>{_tr(lang, "Versions observed")}</th>'
            '</tr></thead><tbody>'
        )
        for name, versions in libraries.items():
            parts.append(
                f'<tr><td>{_e(name)}</td>'
                f'<td>{_e(", ".join(versions))}</td></tr>'
            )
        parts.append(
            '</tbody></table></div><p class="note">'
            + _tr(lang, "Version strings are observations only. A distributor "
                        "backport can make an old-looking version patched, and "
                        "a stale string can hide a newer runtime.")
            + '</p>'
        )
    warnings = bundles.get("warnings") or []
    if warnings:
        parts.append('<ul class="muted-list">')
        for warning in warnings:
            parts.append(f'<li>{_e(warning)}</li>')
        parts.append('</ul>')
    return "".join(parts)


def _audit_section(audit: dict, lang: str = "en") -> str:
    if not isinstance(audit, dict) or not audit:
        return ""
    try:
        score = int(audit.get("risk_score") or 0)
    except (TypeError, ValueError):
        score = 0
    band = str(audit.get("risk_band") or "unknown")
    parts = [
        '<section id="audit">',
        '<h2>' + _tr(lang, "AI-assisted audit") + '</h2>',
        '<div class="audit-head">',
        f'<div class="risk"><div class="risk-value">{score}</div>'
        f'<div class="risk-label">/100 · {_e(band)}</div></div>',
        f'<div class="audit-summary"><p>{_e(audit.get("summary"))}</p>'
        f'<p class="muted">{_tr(lang, "Provider")}: '
        f'{_e(audit.get("provider"))} '
        f'({_e(audit.get("model"))}) · {_e(audit.get("generated_at"))}</p></div>',
        '</div>',
        f'<div class="bar"><span style="width:{max(0, min(100, score))}%"></span></div>',
    ]
    priorities = audit.get("priorities") or []
    if priorities:
        parts.append('<h3>' + _tr(lang, "Priority order") + '</h3>')
        parts.append(
            '<div class="table-wrap"><table><thead><tr>'
            f'<th>#</th><th>{_tr(lang, "Issue")}</th>'
            f'<th>{_tr(lang, "Severity")}</th>'
            f'<th>{_tr(lang, "Validation")}</th>'
            f'<th>{_tr(lang, "Hosts")}</th>'
            f'<th>{_tr(lang, "Why it matters")}</th>'
            f'<th>{_tr(lang, "Action")}</th>'
            '</tr></thead><tbody>'
        )
        for item in priorities:
            hosts = item.get("hosts") or [item.get("host")]
            reproductions = item.get("reproductions")
            if reproductions is None:
                validation = ""
            elif reproductions >= 2:
                validation = f'<span class="vpill ok">{_e(reproductions)}&times;</span>'
            elif reproductions == 1:
                validation = '<span class="vpill warn">1&times;</span>'
            else:
                validation = ('<span class="vpill">'
                              + _tr(lang, "unchecked") + '</span>')
            parts.append(
                '<tr>'
                f'<td>{_e(item.get("rank"))}</td>'
                f'<td>{_e(item.get("title"))}</td>'
                f'<td>{_badge(str(item.get("severity") or "info"))}</td>'
                f'<td>{validation}</td>'
                f'<td>{_e(", ".join(str(host) for host in hosts[:5]))}</td>'
                f'<td>{_e(item.get("why"))}</td>'
                f'<td>{_e(item.get("action"))}</td>'
                '</tr>'
            )
        parts.append('</tbody></table></div>')
    chains = audit.get("chains") or []
    if chains:
        parts.append('<h3>' + _tr(lang, "Correlated hypotheses")
                     + '</h3><div class="cards">')
        for item in chains:
            parts.append(
                '<div class="card chain">'
                f'<h4>{_e(item.get("title"))}</h4>'
                f'<p>{_e(item.get("why"))}</p>'
                f'<p class="note">Next step: {_e(item.get("next_step"))}</p>'
                '</div>'
            )
        parts.append('</div>')
    manual = audit.get("manual_review") or []
    if manual:
        parts.append('<h3>' + _tr(lang, "Manual review queue")
                     + '</h3><ul class="review">')
        for item in manual:
            parts.append(
                f'<li><b>{_e(item.get("title"))}</b> '
                f'<span class="muted">{_e(item.get("host"))}</span> — '
                f'{_e(item.get("reason"))}</li>'
            )
        parts.append('</ul>')
    plan = audit.get("remediation_plan") or []
    if plan:
        parts.append('<h3>' + _tr(lang, "Remediation plan")
                     + '</h3><ol class="plan">')
        for item in plan:
            parts.append(f'<li>{_e(item)}</li>')
        parts.append('</ol>')
    steps = audit.get("next_steps") or []
    if steps:
        parts.append('<h3>' + _tr(lang, "Suggested next steps")
                     + '</h3><ul class="review">')
        for item in steps:
            parts.append(f'<li>{_e(item)}</li>')
        parts.append('</ul>')
    notes = audit.get("notes") or []
    if notes:
        parts.append('<h3>' + _tr(lang, "Audit notes")
                     + '</h3><ul class="muted-list">')
        for item in notes:
            parts.append(f'<li>{_e(item)}</li>')
        parts.append('</ul>')
    parts.append('</section>')
    return "".join(parts)


CSS = """
:root{--bg:#f4f6fb;--bg2:#e9edf7;--panel:#fff;--panel2:#f8faff;--text:#131a2a;
--muted:#5c667c;--line:#e2e7f1;--accent:#3b5bdb;--accent2:#6f8cff;
--accent-soft:#e9edff;--crit:#c0183f;--high:#d9481c;--med:#a86f00;--low:#2f6db3;
--info:#5c667c;--ok:#1c7a4f;--ok-soft:#e5f5ec;--warn:#a86f00;--warn-soft:#fbf1d8;
--bad-soft:#fde7e0;--info-soft:#eef1f7;--code:#f1f4fa;
--shadow:0 10px 30px rgba(19,26,42,.08)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
--bg:#0c111c;--bg2:#131a2a;--panel:#121a29;--panel2:#172132;--text:#e7ecf7;
--muted:#97a3ba;--line:#243049;--accent:#7c96ff;--accent2:#5f7dff;
--accent-soft:#1b2440;--crit:#ff6b91;--high:#ff8a5c;--med:#f0bf5c;--low:#7fb3ff;
--info:#a5afc4;--ok:#5fd39b;--ok-soft:#122a20;--warn:#f0bf5c;--warn-soft:#2a2413;
--bad-soft:#2c1716;--info-soft:#1c2434;--code:#0f1726;--shadow:none}}
:root[data-theme="dark"]{--bg:#0c111c;--bg2:#131a2a;--panel:#121a29;
--panel2:#172132;--text:#e7ecf7;--muted:#97a3ba;--line:#243049;--accent:#7c96ff;
--accent2:#5f7dff;--accent-soft:#1b2440;--crit:#ff6b91;--high:#ff8a5c;
--med:#f0bf5c;--low:#7fb3ff;--info:#a5afc4;--ok:#5fd39b;--ok-soft:#122a20;
--warn:#f0bf5c;--warn-soft:#2a2413;--bad-soft:#2c1716;--info-soft:#1c2434;
--code:#0f1726;--shadow:none}
*{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:74px}
body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,
var(--bg2),transparent 70%),var(--bg);color:var(--text);
font:15px/1.58 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent)}
.nav{position:sticky;top:0;z-index:60;backdrop-filter:blur(12px);
background:color-mix(in srgb,var(--bg) 82%,transparent);border-bottom:1px solid var(--line)}
.nav-inner{max-width:1180px;margin:0 auto;padding:10px 20px;display:flex;
gap:16px;align-items:center}
.brand{font-weight:800;letter-spacing:-.02em;color:var(--text);text-decoration:none;
font-size:15px;white-space:nowrap}
.brand b{color:var(--accent)}
.nav-links{display:flex;gap:2px;flex-wrap:wrap;margin-left:auto}
.nav-links a{padding:6px 10px;border-radius:8px;color:var(--muted);
text-decoration:none;font-size:13px;transition:background .15s,color .15s}
.nav-links a:hover{background:var(--panel);color:var(--text)}
.nav-links a.active{color:var(--accent);background:var(--panel)}
.theme-toggle{border:1px solid var(--line);background:var(--panel);color:var(--muted);
padding:6px 11px;border-radius:9px;font-size:12.5px;cursor:pointer;white-space:nowrap}
.theme-toggle:hover{color:var(--text)}
.wrap{max-width:1180px;margin:0 auto;padding:26px 20px 64px}
header.hero{position:relative;overflow:hidden;background:
linear-gradient(135deg,#16204a,#2f4bd0 55%,#5b7bff);color:#fff;border-radius:20px;
padding:30px 32px;box-shadow:var(--shadow)}
header.hero::after{content:"";position:absolute;inset:0;background-image:
linear-gradient(rgba(255,255,255,.07) 1px,transparent 1px),
linear-gradient(90deg,rgba(255,255,255,.07) 1px,transparent 1px);
background-size:34px 34px;mask-image:radial-gradient(circle at 80% 20%,#000,transparent 70%)}
header.hero>*{position:relative;z-index:1}
header.hero .eyebrow{font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
color:#c3d0ff;margin-bottom:6px}
header.hero h1{margin:0 0 6px;font-size:28px;letter-spacing:-.025em;line-height:1.15}
header.hero p{margin:0;color:#d9e2ff}
header.hero .chips{margin-top:16px;display:flex;flex-wrap:wrap;gap:8px}
.chip{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.24);
padding:5px 10px;border-radius:999px;font-size:12.5px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
gap:12px;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;
padding:15px 16px;box-shadow:var(--shadow)}
.card .k{font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}
.card .v{font-size:25px;font-weight:750;margin-top:6px;line-height:1.1}
.card .v small{font-size:13px;font-weight:500;color:var(--muted)}
.card.warn .v{color:var(--high)}
.card.ok .v{color:var(--ok)}
section{background:var(--panel);border:1px solid var(--line);border-radius:16px;
padding:22px;margin:18px 0;box-shadow:var(--shadow)}
h2{margin:0 0 14px;font-size:20px;letter-spacing:-.015em}
h3{margin:22px 0 10px;font-size:16px}
h4{margin:16px 0 6px;font-size:14px}
p{margin:8px 0}
.muted{color:var(--muted)}
.muted-list{color:var(--muted);font-size:13.5px}
.url{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px;
color:var(--muted);word-break:break-all}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;
font-weight:700;letter-spacing:.045em;color:#fff;vertical-align:middle}
.badge-critical{background:var(--crit)}.badge-high{background:var(--high)}
.badge-medium{background:var(--med)}.badge-low{background:var(--low)}
.badge-info{background:var(--info)}
.pill{display:inline-flex;align-items:center;padding:2px 9px;border-radius:999px;
font-size:10.5px;font-weight:750;letter-spacing:.05em;border:1px solid transparent}
.pill.st-observed{color:var(--ok);background:var(--ok-soft);
border-color:color-mix(in srgb,var(--ok) 40%,transparent)}
.pill.st-partial{color:var(--warn);background:var(--warn-soft);
border-color:color-mix(in srgb,var(--warn) 40%,transparent)}
.pill.st-blocked{color:var(--info);background:var(--info-soft);
border-color:color-mix(in srgb,var(--info) 40%,transparent)}
.vpill{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;
font-weight:650;background:var(--info-soft);color:var(--muted);
border:1px solid var(--line)}
.vpill.ok{background:var(--ok-soft);color:var(--ok);border-color:transparent}
.vpill.warn{background:var(--warn-soft);color:var(--warn);border-color:transparent}
.vpill.bad{background:var(--bad-soft);color:var(--crit);border-color:transparent}
.vpills,.chainrefs{display:flex;gap:6px;flex-wrap:wrap;align-items:center;
margin:8px 0;font-size:12.5px}
.chainrefs b{color:var(--muted);font-size:11.5px;text-transform:uppercase;
letter-spacing:.06em}
.chainchip{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11.5px;
padding:2px 8px;border-radius:6px;background:var(--accent-soft);color:var(--accent);
text-decoration:none}
.legend{display:flex;flex-direction:column;gap:7px;align-items:flex-start;
font-size:13px;color:var(--muted);border:1px dashed var(--line);border-radius:12px;
padding:12px 14px;margin:12px 0}
.legend-row{display:flex;gap:9px;align-items:flex-start}
.legend-row .pill{flex:0 0 auto;margin-top:2px}
.chain-card{border:1px solid var(--line);border-left:6px solid var(--muted);
border-radius:14px;padding:18px 20px;margin:16px 0;background:var(--panel2)}
.chain-card.st-observed{border-left-color:var(--ok)}
.chain-card.st-partial{border-left-color:var(--warn)}
.chain-card.st-blocked{border-left-color:var(--info)}
.chain-top{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.chain-id{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
font-size:11.5px;color:var(--muted)}
.chain-title{margin:8px 0 4px;font-size:17px}
.impact{background:var(--info-soft);border-radius:10px;padding:10px 12px;
font-size:13.5px}
.flow{display:flex;flex-direction:column;margin:16px 0 8px}
.node{position:relative;border:1px solid var(--line);border-radius:12px;
padding:12px 14px 12px 48px;background:var(--panel)}
.node:not(:last-child){margin-bottom:20px}
.node:not(:last-child)::after{content:"";position:absolute;left:27px;bottom:-20px;
height:20px;border-left:2px dashed var(--line)}
.node-num{position:absolute;left:12px;top:12px;width:26px;height:26px;
border-radius:50%;background:var(--accent);color:#fff;font-size:12px;
font-weight:750;display:flex;align-items:center;justify-content:center}
.node.st-observed .node-num{background:var(--ok)}
.node.st-partial .node-num{background:var(--warn)}
.node.st-blocked .node-num{background:var(--info)}
.node-head{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.node-title{font-weight:660}
.node-meta{color:var(--muted);font-size:12.5px;margin-top:3px}
.node p{margin:6px 0 0;font-size:13.5px}
.node-link{display:inline-block;margin-top:8px;font-size:12.5px;
text-decoration:none;font-weight:600}
.proof li,.plan li,.review li{margin:6px 0}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;
vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
tbody tr:hover{background:var(--panel2)}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0;align-items:center}
.filters button{border:1px solid var(--line);background:transparent;color:var(--text);
padding:7px 12px;border-radius:999px;cursor:pointer;font-size:12.5px}
.filters button.active{background:var(--accent);border-color:var(--accent);color:#fff}
.filters input[type=search]{border:1px solid var(--line);background:transparent;
color:var(--text);padding:7px 12px;border-radius:999px;font-size:13px;min-width:220px}
.filters label.chk{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);
padding:7px 12px;border-radius:999px;font-size:12.5px;cursor:pointer;user-select:none}
.filters label.chk input{accent-color:var(--accent)}
.finding{border:1px solid var(--line);border-radius:12px;margin:9px 0;overflow:hidden;
background:var(--panel)}
.finding[open]{box-shadow:var(--shadow)}
.finding summary{cursor:pointer;padding:12px 14px;display:flex;gap:9px;
align-items:center;flex-wrap:wrap;list-style:none}
.finding summary::-webkit-details-marker{display:none}
.finding .idx{color:var(--muted);font-size:12px;min-width:24px}
.finding .title{font-weight:650}
.finding .host{margin-left:auto;color:var(--muted);font-size:12.5px}
.finding-body{padding:6px 16px 16px;border-top:1px solid var(--line)}
.meta{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted);font-size:12.5px}
.decoy{display:flex;gap:10px;padding:12px 14px;border:1px solid var(--warn);
background:var(--warn-soft);border-radius:10px;margin:10px 0;font-size:13.5px}
.decoy b{color:var(--warn)}
pre{position:relative;background:var(--code);border:1px solid var(--line);
border-radius:10px;padding:12px;overflow:auto;font-size:12.5px;
font-family:ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap}
.copy{position:absolute;top:8px;right:8px;font-size:11px;padding:3px 9px;
border-radius:6px;border:1px solid var(--line);background:var(--panel);
color:var(--muted);cursor:pointer;opacity:.8}
.copy:hover{opacity:1;color:var(--text)}
.audit-head{display:flex;gap:18px;align-items:center;flex-wrap:wrap}
.risk{min-width:118px;text-align:center;border:1px solid var(--line);border-radius:14px;
padding:12px;background:var(--panel2)}
.risk-value{font-size:34px;font-weight:800;line-height:1}
.risk-label{color:var(--muted);font-size:12px;margin-top:4px}
.audit-summary{flex:1;min-width:240px}
.bar{height:9px;background:var(--line);border-radius:999px;overflow:hidden;margin:10px 0 4px}
.bar span{display:block;height:100%;background:linear-gradient(90deg,#2f6db3,#b77900,#d9481c)}
.chain{box-shadow:none}
.note{color:var(--muted);font-size:13px}
.note.warn{color:var(--high)}
.private{margin:18px 0;padding:14px 16px;border:1px solid var(--high);
border-left:5px solid var(--high);border-radius:12px;background:var(--bad-soft);
font-size:13.5px}
.tags{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0}
.tag{font-size:11.5px;padding:2px 8px;border-radius:6px;background:var(--accent-soft);
color:var(--accent);font-weight:650}
.tag.alt{background:var(--info-soft);color:var(--muted)}
.mini-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));
gap:10px;margin:12px 0}
.mini{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
padding:10px 12px}
.mini span{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.07em;
color:var(--muted)}
.mini b{font-size:18px}
.bhost{border:1px solid var(--line);border-radius:12px;padding:14px 16px;
margin:12px 0;background:var(--panel2)}
.bhead{display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}
.bhead h4{margin:0}
.asset-list summary{cursor:pointer;color:var(--accent);font-size:13px;margin-top:8px}
.empty{color:var(--muted);font-style:italic}
footer{color:var(--muted);font-size:12.5px;text-align:center;margin-top:28px}
@media (max-width:640px){.nav-links{display:none}header.hero{padding:22px}
.wrap{padding:18px 12px 48px}section{padding:16px}}
@media print{body{background:#fff}.nav,.filters,.copy{display:none}
details{open:true}section,header.hero,.card,.chain-card{box-shadow:none}
header.hero{background:#16204a}}
"""

JS = """
(function(){
  var root=document.documentElement;
  var THEME_KEY='webwarden-theme';
  var toggle=document.getElementById('theme');
  var modes=['auto','light','dark'];
  function current(){
    try{return localStorage.getItem(THEME_KEY)||'auto'}catch(e){return 'auto'}
  }
  function apply(mode){
    if(mode==='auto'){root.removeAttribute('data-theme')}
    else{root.setAttribute('data-theme',mode)}
    if(toggle){
      toggle.textContent='Theme: '+(mode.charAt(0).toUpperCase()+mode.slice(1));
      toggle.setAttribute('aria-label','Theme: '+mode);
    }
    try{localStorage.setItem(THEME_KEY,mode)}catch(e){}
  }
  apply(current());
  if(toggle){toggle.addEventListener('click',function(){
    var mode=current();
    apply(modes[(modes.indexOf(mode)+1)%modes.length]);
  })}

  var buttons=document.querySelectorAll('[data-filter]');
  var search=document.getElementById('search');
  var validOnly=document.getElementById('valid-only');
  var hideDecoys=document.getElementById('hide-decoys');
  function applyFilters(){
    var active=document.querySelector('[data-filter].active');
    var sev=active?active.getAttribute('data-filter'):'all';
    var q=(search&&search.value||'').toLowerCase().trim();
    document.querySelectorAll('.finding').forEach(function(el){
      var okSev=sev==='all'||el.getAttribute('data-severity')===sev;
      var okQ=!q||(el.getAttribute('data-search')||'').indexOf(q)>=0;
      var okValid=!validOnly||!validOnly.checked||el.getAttribute('data-verified')==='1';
      var okDecoy=!hideDecoys||!hideDecoys.checked||el.getAttribute('data-decoy')!=='1';
      el.style.display=(okSev&&okQ&&okValid&&okDecoy)?'':'none';
    });
  }
  buttons.forEach(function(btn){btn.addEventListener('click',function(){
    buttons.forEach(function(other){other.classList.remove('active')});
    btn.classList.add('active');applyFilters();
  })});
  if(search){search.addEventListener('input',applyFilters)}
  if(validOnly){validOnly.addEventListener('change',applyFilters)}
  if(hideDecoys){hideDecoys.addEventListener('change',applyFilters)}

  document.querySelectorAll('pre').forEach(function(pre){
    var btn=document.createElement('button');
    btn.type='button';btn.className='copy';btn.textContent='Copy';
    btn.addEventListener('click',function(){
      var text=pre.textContent;
      function done(){btn.textContent='Copied';setTimeout(function(){
        btn.textContent='Copy'},1400)}
      if(navigator.clipboard&&navigator.clipboard.writeText){
        navigator.clipboard.writeText(text).then(done,function(){});
      }else{
        var area=document.createElement('textarea');
        area.value=text;document.body.appendChild(area);area.select();
        try{document.execCommand('copy')}catch(e){}
        document.body.removeChild(area);done();
      }
    });
    pre.appendChild(btn);
  });

  var links=document.querySelectorAll('.nav-links a[href^="#"]');
  var targets=[];
  links.forEach(function(link){
    var id=link.getAttribute('href').slice(1);
    var el=document.getElementById(id);
    if(el){targets.push({link:link,el:el})}
  });
  if('IntersectionObserver' in window&&targets.length){
    var observer=new IntersectionObserver(function(entries){
      entries.forEach(function(entry){
        if(!entry.isIntersecting){return}
        targets.forEach(function(item){
          item.link.classList.toggle('active',item.el===entry.target);
        });
      });
    },{rootMargin:'-45% 0px -50% 0px',threshold:0});
    targets.forEach(function(item){observer.observe(item.el)});
  }
})();
"""


def _recon_section(result: ScanResult, lang: str = "en") -> str:
    recon = result.recon or {}
    parts = ['<section id="recon"><h2>' + _tr(lang, "Recon") + '</h2>']
    addresses = recon.get("addresses") or {}
    dns_records = recon.get("dns") or {}
    rows = []
    for record in ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA"):
        if record in ("A", "AAAA"):
            values = addresses.get(record) or []
        else:
            values = dns_records.get(record) or []
        if values:
            rows.append(f'<tr><td>{record}</td><td>{_e(", ".join(values[:10]))}</td></tr>')
    if rows:
        parts.append(
            '<h3>DNS</h3><div class="table-wrap"><table><thead><tr>'
            f'<th>{_tr(lang, "Record")}</th><th>{_tr(lang, "Values")}</th>'
            '</tr></thead><tbody>'
            + "".join(rows)
            + "</tbody></table></div>"
        )
    hosts = recon.get("hosts") or []
    if hosts:
        parts.append('<h3>' + _tr(lang, "Live HTTP hosts")
                     + '</h3><div class="table-wrap"><table><thead><tr>'
                     f'<th>{_tr(lang, "Host")}</th><th>URL</th>'
                     f'<th>{_tr(lang, "Status")}</th>'
                     f'<th>{_tr(lang, "Title")}</th>'
                     f'<th>{_tr(lang, "Server")}</th>'
                     f'<th>{_tr(lang, "Tech")}</th></tr></thead><tbody>')
        for host in hosts:
            parts.append(
                "<tr>"
                f'<td>{_e(host.get("host"))}</td>'
                f'<td class="url">{_e(host.get("url"))}</td>'
                f'<td>{_e(host.get("status"))}</td>'
                f'<td>{_e(host.get("title"))}</td>'
                f'<td>{_e(host.get("server"))}</td>'
                f'<td>{_e(", ".join(host.get("tech") or []))}</td>'
                "</tr>"
            )
        parts.append("</tbody></table></div>")
    ports = (recon.get("ports") or {}).get("ports") or []
    if ports:
        parts.append('<h3>' + _tr(lang, "Open ports")
                     + '</h3><div class="table-wrap"><table><thead><tr>'
                     f'<th>{_tr(lang, "IP")}</th><th>{_tr(lang, "Port")}</th>'
                     f'<th>{_tr(lang, "Service")}</th></tr></thead><tbody>')
        for item in ports:
            parts.append(
                f'<tr><td>{_e(item.get("ip"))}</td>'
                f'<td>{_e(item.get("port"))}</td>'
                f'<td>{_e(item.get("service"))}</td></tr>'
            )
        parts.append("</tbody></table></div>")
    header_info = recon.get("headers") or {}
    matrix = header_info.get("matrix") or []
    if matrix:
        parts.append(
            '<h3>' + _tr(lang, "Security header coverage") + '</h3>'
            '<p class="note">'
            + _tr(lang, "Presence per endpoint; HSTS only applies to HTTPS "
                        "responses.") + '</p>'
            '<div class="table-wrap"><table><thead><tr>'
            f'<th>{_tr(lang, "Endpoint")}</th><th>HTTP</th><th>HSTS</th>'
            '<th>CSP</th><th>XCTO</th><th>XFO</th>'
            f'<th>{_tr(lang, "Referrer")}</th>'
            f'<th>{_tr(lang, "Permissions")}</th>'
            '</tr></thead><tbody>'
        )
        for entry in matrix[:100]:
            present = entry.get("present") or {}
            cells = "".join(
                f'<td>{_tr(lang, "yes") if present.get(label) else _tr(lang, "no")}</td>'
                for label in (
                    "Strict-Transport-Security", "Content-Security-Policy",
                    "X-Content-Type-Options", "X-Frame-Options",
                    "Referrer-Policy", "Permissions-Policy",
                )
            )
            parts.append(
                f'<tr><td class="url">{_e(entry.get("url"))}</td>'
                f'<td>{_e(entry.get("status"))}</td>{cells}</tr>'
            )
        parts.append("</tbody></table></div>")
    security = header_info.get("security_txt") or {}
    if security:
        parts.append(
            '<h3>security.txt</h3><div class="table-wrap"><table><thead><tr>'
            f'<th>{_tr(lang, "Host")}</th><th>{_tr(lang, "Status")}</th>'
            f'<th>{_tr(lang, "Contact")}</th>'
            f'<th>{_tr(lang, "Expires")}</th>'
            '</tr></thead><tbody>'
        )
        for host, entry in sorted(security.items()):
            status = (_tr(lang, "valid") if entry.get("valid")
                      else (entry.get("reason") or f"HTTP {entry.get('status')}"))
            if entry.get("expired"):
                status += " " + _tr(lang, "(expired)")
            parts.append(
                f'<tr><td>{_e(host)}</td><td>{_e(status)}</td>'
                f'<td>{_e(", ".join(entry.get("contacts") or []))}</td>'
                f'<td>{_e(entry.get("expires"))}</td></tr>'
            )
        parts.append("</tbody></table></div>")
    client = recon.get("client") or {}
    if client:
        parts.append(
            '<h3>' + _tr(lang, "Client-side exposure") + '</h3>'
            '<p class="note">'
            + _tr(lang, "Secret values are redacted here; raw responses stay "
                        "in the private evidence directory.") + " "
            + _tr(lang, "Files scanned") + f': {_e(client.get("files_scanned", 0))} · '
            + _tr(lang, "secret hits") + f': {_e(client.get("secrets", 0))} · '
            + _tr(lang, "source maps") + f': {_e(len(client.get("source_maps") or []))} · '
            + _tr(lang, "credential-like URL parameters")
            + f': {_e(client.get("url_tokens", 0))} · '
            + _tr(lang, "robots.txt path probing") + ': '
            + (_tr(lang, "enabled") if client.get("robots_paths")
               else _tr(lang, "not requested")) + '.</p>'
        )
        hits = client.get("secret_hits") or []
        if hits:
            parts.append(
                '<div class="table-wrap"><table><thead><tr>'
                f'<th>{_tr(lang, "Host")}</th><th>{_tr(lang, "Kind")}</th>'
                f'<th>{_tr(lang, "Severity")}</th>'
                f'<th>{_tr(lang, "Redacted value")}</th>'
                f'<th>{_tr(lang, "Files")}</th></tr></thead><tbody>'
            )
            for hit in hits[:30]:
                parts.append(
                    f'<tr><td>{_e(hit.get("host"))}</td>'
                    f'<td>{_e(hit.get("kind"))}</td>'
                    f'<td>{_badge(hit.get("severity"))}</td>'
                    f'<td>{_e(hit.get("redacted"))}</td>'
                    f'<td>{len(hit.get("files") or [])}</td></tr>'
                )
            parts.append("</tbody></table></div>")
        maps = client.get("source_maps") or []
        if maps:
            parts.append(
                '<div class="table-wrap"><table><thead><tr>'
                f'<th>{_tr(lang, "Source map")}</th>'
                f'<th>{_tr(lang, "Referenced by")}</th>'
                f'<th>{_tr(lang, "Sources")}</th>'
                '</tr></thead><tbody>'
            )
            for entry in maps[:20]:
                parts.append(
                    f'<tr><td class="url">{_e(entry.get("url"))}</td>'
                    f'<td class="url">{_e(entry.get("script"))}</td>'
                    f'<td>{_e(entry.get("sources"))}</td></tr>'
                )
            parts.append("</tbody></table></div>")
    parts.append(_bundles_section(recon.get("bundles") or {}, lang))
    parts.append(_probes_section(recon, lang))
    components = recon.get("components") or {}
    if components:
        parts.append('<h3>' + _tr(lang, "Component versions")
                     + '</h3><div class="table-wrap"><table>'
                     f'<thead><tr><th>{_tr(lang, "Component")}</th>'
                     f'<th>{_tr(lang, "Version")}</th>'
                     f'<th>{_tr(lang, "Evidence")}</th>'
                     f'<th>{_tr(lang, "Hosts")}</th></tr></thead><tbody>')
        for name, info in components.items():
            if not isinstance(info, dict):
                continue
            parts.append(
                f'<tr><td>{_e(name)}</td><td>{_e(info.get("version"))}</td>'
                f'<td>{_e(info.get("evidence"))}</td>'
                f'<td>{_e(", ".join(info.get("hosts") or []))}</td></tr>'
            )
        parts.append("</tbody></table></div>")
    bypass = recon.get("bypass") or {}
    if bypass.get("enabled"):
        attempts = bypass.get("attempts") or []
        parts.append('<h3>' + _tr(lang, "Access-control bypass checks")
                     + '</h3>')
        if attempts:
            parts.append('<div class="table-wrap"><table><thead><tr>'
                         f'<th>{_tr(lang, "Host")}</th><th>Path</th>'
                         f'<th>{_tr(lang, "Baseline")}</th>'
                         f'<th>{_tr(lang, "Variants")}</th>'
                         f'<th>{_tr(lang, "Result")}</th>'
                         '</tr></thead><tbody>')
            for attempt in attempts:
                if attempt.get("bypass"):
                    outcome = (f'{_tr(lang, "BYPASS via")} '
                               f'{_e(attempt.get("technique"))} '
                               f'(HTTP {_e(attempt.get("bypass_status"))})')
                else:
                    outcome = _tr(lang, "no bypass")
                parts.append(
                    f'<tr><td>{_e(attempt.get("host"))}</td>'
                    f'<td>{_e(attempt.get("path"))}</td>'
                    f'<td>{_e(attempt.get("baseline"))}</td>'
                    f'<td>{_e(attempt.get("variants"))}</td>'
                    f'<td>{outcome}</td></tr>'
                )
            parts.append("</tbody></table></div>")
        else:
            parts.append("<p>"
                         + _tr(lang, "No sensitive path returned HTTP 401/403.")
                         + "</p>")
    takeover = recon.get("takeover") or {}
    if takeover.get("enabled"):
        candidates = takeover.get("candidates") or []
        parts.append('<h3>' + _tr(lang, "Subdomain takeover candidates")
                     + '</h3>')
        if candidates:
            parts.append('<div class="table-wrap"><table><thead><tr>'
                         f'<th>{_tr(lang, "Host")}</th><th>CNAME</th>'
                         f'<th>{_tr(lang, "Provider")}</th>'
                         '<th>HTTP</th>'
                         f'<th>{_tr(lang, "Result")}</th>'
                         '</tr></thead><tbody>')
            for item in candidates:
                verdict = (_tr(lang, "candidate") if item.get("takeover")
                           else _tr(lang, "no marker"))
                parts.append(
                    f'<tr><td>{_e(item.get("host"))}</td>'
                    f'<td>{_e(item.get("cname"))}</td>'
                    f'<td>{_e(item.get("provider"))}</td>'
                    f'<td>{_e(item.get("http_status"))}</td>'
                    f'<td>{verdict}</td></tr>'
                )
            parts.append("</tbody></table></div>")
        else:
            parts.append(
                "<p>" + _tr(lang, "No host matched a third-party CNAME plus an "
                                  "unclaimed-resource page.") + "</p>"
            )
    parts.append("</section>")
    return "".join(parts)


def _readiness_section(result: ScanResult, lang: str = "en") -> str:
    findings = result.sorted_findings()
    actionable = [
        finding for finding in findings
        if finding.verified and finding.severity in ("critical", "high", "medium")
        and not finding.decoy_suspected
    ]
    informational = [
        finding for finding in findings
        if finding.severity in ("info", "low")
    ]
    decoys = [finding for finding in findings if finding.decoy_suspected]
    parts = ['<section id="readiness"><h2>'
             + _tr(lang, "Submission readiness") + '</h2>']
    parts.append(
        '<p class="note">'
        + _tr(lang, "Guidance only. Programs reject out-of-scope, duplicate, "
                    "purely informational, or impact-free reports.") + '</p>'
        '<div class="table-wrap"><table><thead><tr>'
        f'<th>{_tr(lang, "Bucket")}</th><th>{_tr(lang, "Count")}</th>'
        '</tr></thead><tbody>'
        '<tr><td>'
        + _tr(lang, "Verified critical/high/medium candidates")
        + f'</td><td>{len(actionable)}</td></tr>'
        '<tr><td>' + _tr(lang, "Informational/low items (usually not rewarded)")
        + f'</td><td>{len(informational)}</td></tr>'
        '<tr><td>' + _tr(lang, "Decoy/canary findings excluded from scoring")
        + f'</td><td>{len(decoys)}</td></tr>'
        '</tbody></table></div>'
    )
    if actionable:
        parts.append('<ul class="review">')
        for finding in actionable[:20]:
            parts.append(
                f'<li>{_badge(finding.severity)} {_e(finding.title)} '
                f'<span class="muted">({_e(finding.host)})</span></li>'
            )
        parts.append("</ul>")
    checklist = (
        "Confirm every affected host is explicitly in scope.",
        "Confirm the vulnerability class is not excluded by the program.",
        "Attach the reproduction command, raw evidence, and a concrete impact "
        "statement.",
        "Treat tokens and secrets as inert evidence: do not authenticate with "
        "harvested credentials; ask for a sanctioned test token if needed.",
        "Check prior disclosures for duplicates.",
        "Submit informational-only items as a note, not a vulnerability "
        "report.",
    )
    parts.append('<h3>' + _tr(lang, "Before submitting")
                 + '</h3><ul class="review">')
    for item in checklist:
        parts.append(f"<li>{_tr(lang, item)}</li>")
    parts.append("</ul></section>")
    return "".join(parts)


NAV_ITEMS = (
    ("summary", "Summary"),
    ("chains", "Chains"),
    ("readiness", "Readiness"),
    ("findings", "Findings"),
    ("recon", "Recon"),
    ("audit", "Audit"),
)


def render_html(result: ScanResult, lang: str = "en") -> str:
    findings = result.sorted_findings()
    counts = Counter(finding.severity for finding in findings)
    audit = result.audit if isinstance(result.audit, dict) else {}
    try:
        score = int(audit.get("risk_score"))
    except (TypeError, ValueError):
        score = None
    stats = result.stats or {}
    recon = result.recon or {}
    license_info = recon.get("license") or {}
    chains = recon.get("chains") or {}
    bundles = recon.get("bundles") or {}
    grouped = _grouped(findings)
    verified = sum(1 for finding in findings if finding.verified)
    decoys = sum(1 for finding in findings if finding.decoy_suspected)
    stable = sum(1 for finding in findings if finding.stable is True)
    generated = (
        audit.get("generated_at") or result.finished_at or result.started_at
    )
    chain_total = chains.get("total", 0) if chains.get("enabled") else 0
    chain_observed = chains.get("observed", 0) if chains.get("enabled") else 0
    cards = [
        ("Risk score",
         f'{score}<small>/100</small>' if score is not None
         else _tr(lang, "n/a"),
         ""),
        ("Critical / High", f'{counts.get("critical", 0)} / {counts.get("high", 0)}',
         "warn" if counts.get("critical", 0) or counts.get("high", 0) else "ok"),
        ("Medium / Low", f'{counts.get("medium", 0)} / {counts.get("low", 0)}', ""),
        ("Verified", f'{verified}<small>/{len(findings)}</small>',
         "ok" if findings and verified == len(findings) else ""),
        ("Stable", str(stable), ""),
        ("Chains", f'{chain_observed}<small>obs / {chain_total}</small>',
         "ok" if chain_observed else ""),
        ("Build drift", str(bundles.get("drift", 0) if bundles.get("enabled") else 0),
         "warn" if bundles.get("drift") else ""),
        ("Missing chunks",
         str(bundles.get("missing_chunks", 0) if bundles.get("enabled") else 0),
         "warn" if bundles.get("missing_chunks") else ""),
        ("Requests", str(stats.get("requests", 0)), ""),
    ]
    chain_lookup: dict[str, list[tuple[str, str]]] = {}
    for chain in chains.get("items") or []:
        for link in chain.get("links") or []:
            key = (
                f"{(link.get('title') or '').lower()}|"
                f"{(link.get('host') or '').lower()}"
            )
            chain_lookup.setdefault(key, []).append(
                (str(chain.get("id") or ""), str(link.get("status") or "partial"))
            )
    nav_links = "".join(
        f'<a href="#{anchor}">{_tr(lang, label)}</a>'
        for anchor, label in NAV_ITEMS
    )
    parts = [
        f'<!doctype html><html lang="{_lang(lang)}"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{_tr(lang, 'webwarden report')} — {_e(result.target)}</title>",
        "<script>(function(){try{var m=localStorage.getItem('webwarden-theme');"
        "if(m==='light'||m==='dark'){document.documentElement.setAttribute("
        "'data-theme',m)}}catch(e){}})();</script>",
        f"<style>{CSS}</style></head><body>",
        '<nav class="nav"><div class="nav-inner">'
        '<a class="brand" href="#top"><b>web</b>warden</a>'
        f'<div class="nav-links">{nav_links}</div>'
        '<button id="theme" class="theme-toggle" type="button">'
        + _tr(lang, "Theme: Auto") + '</button>'
        '</div></nav>',
        '<div class="wrap" id="top">',
        '<header class="hero">',
        '<div class="eyebrow">'
        + _tr(lang, "Authorized security assessment") + '</div>',
        f"<h1>{_e(result.target)}</h1>",
        f"<p>{_tr(lang, 'Generated')} {_e(generated)} · webwarden "
        f"{_e(result.version)}</p>",
        '<div class="chips">',
        f'<span class="chip">{_tr(lang, "Scope")}: '
        f'{_e(", ".join(result.scopes))}</span>',
        f'<span class="chip">{_tr(lang, "Authorization")}: '
        + _tr(lang, "operator flag (unverified)" if result.authorized
               else "not confirmed") + '</span>',
        '<span class="chip">' + _tr(lang, "Read-only checks") + '</span>',
        *(
            [
                f'<span class="chip">{_tr(lang, "License")}: '
                f'{_e(license_info.get("watermark", ""))}</span>'
            ]
            if license_info
            else []
        ),
        f'<span class="chip">{len(findings)} {_tr(lang, "finding(s)")}</span>',
        f'<span class="chip">{chain_total} {_tr(lang, "chain(s)")}</span>',
        "</div></header>",
        '<div class="private">'
        + _tr(lang, "PRIVATE — VERBATIM EVIDENCE.") + ' '
        + _tr(lang, "The <code>evidence/</code> directory and the evidence "
                    "blocks below are exact server responses. They are not "
                    "truncated or redacted and may contain live passwords, API "
                    "keys, cookies, tokens, and personal data. Keep this report "
                    "owner-only and redact third-party secrets only if the "
                    "disclosure policy requires it. The optional AI audit "
                    "receives scrubbed excerpts only; the local evidence does "
                    "not.") + '</div>',
        '<div class="cards" id="summary">',
    ]
    for label, value, tone in cards:
        css = f" {tone}" if tone else ""
        parts.append(
            f'<div class="card{css}"><div class="k">{_e(_tr(lang, label))}</div>'
            f'<div class="v">{value}</div></div>'
        )
    parts.append("</div>")
    parts.append(_audit_section(audit, lang))
    parts.append(_chains_section(chains, findings, lang))
    if decoys:
        parts.append(
            f'<section id="decoys"><h2>'
            + _tr(lang, "Decoy / canary signals") + '</h2>'
            f'<p class="note">{decoys} '
            + _tr(lang, "finding(s) advertise themselves as a honeypot, decoy, "
                        "canary, or test credential. They are shown for "
                        "completeness but excluded from the risk score and "
                        "priority ordering.") + '</p><ul class="review">'
        )
        for finding in findings:
            if not finding.decoy_suspected:
                continue
            parts.append(
                f'<li>{_badge(finding.severity)} {_e(finding.title)} '
                f'<span class="muted">({_e(finding.host)})</span> — '
                f'{_e(finding.decoy_reason or _tr(lang, "decoy marker"))}</li>'
            )
        parts.append("</ul></section>")
    parts.append(_readiness_section(result, lang))
    parts.append(_scenarios_section(findings, lang))

    parts.append('<section id="findings"><h2>'
                 + _tr(lang, "Grouped findings") + '</h2>')
    if grouped:
        parts.append('<div class="table-wrap"><table><thead><tr>'
                     f'<th>{_tr(lang, "Issue")}</th>'
                     f'<th>{_tr(lang, "Severity")}</th>'
                     f'<th>{_tr(lang, "Category")}</th>'
                     f'<th>{_tr(lang, "Affected hosts")}</th>'
                     f'<th>{_tr(lang, "Count")}</th></tr></thead><tbody>')
        for title, severity, category, items in grouped:
            hosts = sorted({item.host for item in items})
            shown = ", ".join(hosts[:6])
            if len(hosts) > 6:
                shown += " " + _tr(lang, "(+{n} more)").format(
                    n=len(hosts) - 6)
            parts.append(
                f'<tr><td>{_e(title)}</td><td>{_badge(severity)}</td>'
                f'<td>{_e(category)}</td><td>{_e(shown)}</td>'
                f'<td>{len(items)}</td></tr>'
            )
        parts.append("</tbody></table></div>")
    else:
        parts.append(
            "<p>" + _tr(lang, "No findings were produced. This does not prove "
                              "the target is secure; manual testing is still "
                              "required.") + "</p>"
        )
    parts.append("</section>")

    parts.append('<section id="details"><h2>'
                 + _tr(lang, "Finding details") + '</h2>')
    parts.append('<div class="filters">')
    parts.append('<button class="active" data-filter="all">'
                 + _tr(lang, "All") + '</button>')
    for severity in SEVERITIES:
        if counts.get(severity):
            parts.append(
                f'<button data-filter="{severity}">'
                f'{SEVERITY_LABEL[severity]} ({counts[severity]})</button>'
            )
    parts.append(
        '<label class="chk"><input type="checkbox" id="valid-only"> '
        + _tr(lang, "Verified only") + '</label>'
        '<label class="chk"><input type="checkbox" id="hide-decoys"> '
        + _tr(lang, "Hide decoys") + '</label>'
        '<input id="search" type="search" placeholder="'
        + _tr(lang, "Search findings") + '">'
    )
    parts.append("</div>")
    for index, finding in enumerate(findings, start=1):
        parts.append(_finding_block(index, finding, chain_lookup, lang))
    parts.append("</section>")

    if result.warnings:
        parts.append('<section id="warnings"><h2>'
                     + _tr(lang, "Warnings") + '</h2><ul class="review">')
        for warning in result.warnings:
            parts.append(f"<li>{_e(warning)}</li>")
        parts.append("</ul></section>")

    parts.append(_recon_section(result, lang))
    limitations = [
        "Automated checks are read-only (GET/HEAD). Items marked "
        "needs manual verification must be confirmed before reporting.",
        "AI-assisted audit re-ranks observed findings only. It does not prove "
        "exploitability and must not be treated as an independent scanner.",
        "CVE candidates are version/CPE matches; confirm the exact build and backports.",
        "Evidence bodies are stored verbatim and unredacted up to --evidence-bytes "
        "(default 5 MiB, ceiling 64 MiB). A finding states when its capture hit "
        "that limit; poc.sh can retrieve the complete response.",
        "Evidence-linked chains connect only conditions this scan observed. "
        "Observed means every link reproduced on independent requests; partial "
        "means at least one link needs manual confirmation; blocked means a link "
        "carries a decoy marker or the chain needs an action outside the "
        "read-only boundary. No chain was executed: no session was hijacked, no "
        "credential replayed, and no resource claimed.",
        "Decoy/canary markers are detected from response text. A match warns "
        "that a finding may be intentional, not proof; decoy findings are "
        "excluded from the risk score and priority ordering.",
        "Bundle/build drift compares served HTML with served artifacts. Drift is "
        "a deployment-consistency signal, not evidence of an exploitable "
        "condition, and version strings can be stale or backported.",
        "A negative bypass, chain, or takeover result does not prove that no "
        "issue exists.",
        "Client-side secret matches are pattern-based candidates, never validated "
        "or replayed; report text is redacted and raw responses stay in the "
        "private evidence directory.",
        "Credential-like URL parameters are flagged from crawl output without "
        "being requested.",
        "No login attempts, brute force, writes, or persistence actions are performed.",
    ]
    parts.append('<section id="limitations"><h2>'
                 + _tr(lang, "Limitations") + '</h2><ul class="review">')
    for item in limitations:
        parts.append(f"<li>{_e(_tr(lang, item))}</li>")
    parts.append("</ul></section>")
    parts.append(
        '<footer>'
        + _tr(lang, "Generated by webwarden. Use only within an authorized scope.")
        + '</footer>'
    )
    parts.append(f"<script>{JS}</script>")
    parts.append("</div></body></html>")
    return "".join(parts)
