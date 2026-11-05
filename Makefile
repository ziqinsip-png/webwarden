# webwarden + datz — build, test, and licence targets
#
#   make                 ikhtisar target
#   make datz            engine zipapp + dist/datz.py satu file
#   make test            seluruh suite (tanpa dependensi eksternal)
#   make pro LICENSE_KEY=DATZ1.xxxx.xxxx
#   make key CUSTOMER="Nama" DAYS=365      (penerbit, perlu DATZ_SIGNING_KEY)
#
# Read LICENSE before commercial use: the source is public, running it past the
# 20-day trial needs a signed key.

PYTHON ?= python3
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
DIST   ?= dist
BUILD  := .build
ENGINE := webwarden.pyz
DATZ   := $(DIST)/datz.py
TESTS  := tests.test_webwarden tests.test_datz tests.test_licensing \
          tests.test_enrichment tests.test_upload_audit tests.test_access_audit
SOURCES := $(wildcard webwarden/*.py)

.PHONY: help all engine datz wheel lite pro key status test install uninstall clean distclean

help:
	@echo "webwarden $(ENGINE) + datz console"
	@echo ""
	@echo "  make all       engine zipapp lalu dist/datz.py satu file"
	@echo "  make engine    bangun $(ENGINE) dari source"
	@echo "  make datz      embed engine ke $(DATZ) (payload diverifikasi SHA-256)"
	@echo "  make wheel     bangun roda pip dari pyproject.toml"
	@echo "  make test       $(words $(TESTS)) modul unittest"
	@echo "  make lite      periksa artefak tanpa lisensi (mode uji 20 hari)"
	@echo "  make pro LICENSE_KEY=DATZ1.xxx.xxx   pasang kunci Pro di mesin ini"
	@echo "  make status    tier, sisa hari, dan sumber kunci"
	@echo "  make key CUSTOMER=\"Nama\" DAYS=365    terbitkan kunci (penerbit saja)"
	@echo "  make install   pasang ke $(BINDIR) (PREFIX=/usr untuk /usr/bin)"
	@echo "  make clean     hapus $(BUILD) dan $(DIST)"
	@echo ""
	@echo "  lisensi: baca LICENSE. Source publik bukan berarti gratis."
	@echo "  pembelian: https://lisensi.ziqintzy.my.id/"

all: datz

engine: $(ENGINE)

$(ENGINE): $(SOURCES)
	@rm -rf $(BUILD)
	@mkdir -p $(BUILD)
	@printf 'import sys\nfrom webwarden.cli import main\n\nsys.exit(main())\n' > $(BUILD)/__main__.py
	@cp -r webwarden $(BUILD)/webwarden
	@rm -rf $(BUILD)/webwarden/__pycache__
	$(PYTHON) -m zipapp $(BUILD) -o $(ENGINE) -p "/usr/bin/env python3" -c
	@echo "engine : $(ENGINE) ($$(wc -c < $(ENGINE)) byte)"

datz: $(DATZ)

$(DATZ): $(ENGINE) datz.py pack_datz.py
	$(PYTHON) pack_datz.py --engine $(ENGINE) --template datz.py --out $(DATZ)

wheel:
	$(PYTHON) -m pip install --quiet build
	$(PYTHON) -m build --wheel --outdir $(DIST)

lite: $(DATZ)
	@echo "--- artefak Lite (tanpa kunci) ---"
	@$(PYTHON) $(DATZ) --version
	@$(PYTHON) -c "import sys; sys.path.insert(0,'.'); from webwarden import licensing as l; print('trial aktif : %d hari, lalu lisensi diperlukan' % l.TRIAL_DAYS); print('beli kunci   : https://lisensi.ziqintzy.my.id/'); print('aktivasi    : make pro LICENSE_KEY=...')"

pro:
	@test -n "$(LICENSE_KEY)" || { echo "make pro LICENSE_KEY=DATZ1.xxxx.xxxx"; exit 2; }
	$(PYTHON) $(if $(wildcard $(DATZ)),$(DATZ),datz.py) --license "$(LICENSE_KEY)"
	@$(PYTHON) -m webwarden license status

key:
	@test -n "$$DATZ_SIGNING_KEY" || { echo "export DATZ_SIGNING_KEY=<64 hex> dulu; kunci privat tidak pernah ikut repo"; exit 2; }
	@mkdir -p $(DIST)
	$(PYTHON) mint_key.py --customer "$(CUSTOMER)" \
		$(if $(PRODUCT),--product $(PRODUCT),) \
		$(if $(DAYS),--days $(DAYS),) \
		$(if $(MAX_HOSTS),--max-hosts $(MAX_HOSTS),) \
		--out "$(DIST)/license-$(CUSTOMER).key"
	@echo "kunci ditulis ke $(DIST)/license-$(CUSTOMER).key (chmod 600) — kirim ke pelanggan, jangan di-commit"

status:
	@$(PYTHON) -m webwarden license status

test:
	@echo "webwarden: $(words $(TESTS)) modul"
	$(PYTHON) -m unittest $(TESTS)

install: datz
	install -d $(BINDIR)
	install -m 0755 $(DATZ) $(BINDIR)/datz
	install -m 0755 $(ENGINE) $(BINDIR)/webwarden
	@echo "terpasang: $(BINDIR)/datz dan $(BINDIR)/webwarden"
	@echo "jalankan : datz --help"

uninstall:
	rm -f $(BINDIR)/datz $(BINDIR)/webwarden

clean:
	rm -rf $(BUILD) $(DIST)
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

distclean: clean
	rm -f $(ENGINE)
