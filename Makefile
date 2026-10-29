SHELL := /bin/bash
.PHONY: all pull up fetch ingest analyze report test clean verify-deps evidence

SAMPLES := cobaltstrike-20240115 cobaltstrike-20240320 qakbot-20231102 icedid-20231205

all: verify-deps pull fetch up ingest analyze report test evidence

verify-deps:
	@command -v docker >/dev/null 2>&1 || { echo "Docker is required"; exit 1; }
	@command -v docker-compose >/dev/null 2>&1 || command -v docker compose >/dev/null 2>&1 || { echo "Docker Compose is required"; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { echo "Python3 is required"; exit 1; }

pull:
	docker compose pull

up:
	docker compose up -d zeek suricata

fetch:
	./scripts/fetch_samples.sh

ingest:
	@for sample in $(SAMPLES); do \
		echo "==> Ingesting PCAP for $$sample"; \
		./scripts/ingest.sh $$sample; \
	done

analyze:
	@for sample in $(SAMPLES); do \
		echo "==> Analyzing beacons and indicators for $$sample"; \
		python3 -m analysis.beaconing --sample-id $$sample; \
		python3 -m analysis.iocs --sample-id $$sample; \
	done

report:
	@for sample in $(SAMPLES); do \
		echo "==> Generating threat report for $$sample"; \
		python3 -m analysis.report --sample-id $$sample; \
	done

test:
	python3 -m pytest tests/

evidence:
	@mkdir -p evidence
	@echo "# Auto-generated checksums for lab artifacts" > evidence/SHA256SUMS
	@sha256sum pcap/samples/*.pcap >> evidence/SHA256SUMS 2>/dev/null || true
	@sha256sum out/*/REPORT.md >> evidence/SHA256SUMS 2>/dev/null || true
	@echo "Evidence hashes recorded in evidence/SHA256SUMS"

clean:
	docker compose down -v
	rm -rf out/*
	rm -f intel/intel.dat
	rm -f evidence/SHA256SUMS
