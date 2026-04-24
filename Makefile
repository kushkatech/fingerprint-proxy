.PHONY: test
test:
	cargo test --workspace --all-targets

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: fmt-check
fmt-check:
	cargo fmt --all --check

.PHONY: lint
lint:
	cargo clippy --workspace --all-targets -- -D warnings

.PHONY: docker-demo
docker-demo:
	docker compose -f docker-compose.local.yml up --build
