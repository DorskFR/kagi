LOCK := flock $(HOME)/.cache/kagi-build.lock

.PHONY: fmt lint test

fmt:
	cargo fmt
	npm run format

lint:
	cargo fmt --check
	$(LOCK) cargo clippy --all-targets --all-features --locked -- -D warnings
	npm run check
	npm run lint

test:  ## Also regenerates the TypeScript wire types in ts/generated
	$(LOCK) cargo test --locked
	$(LOCK) cargo test --locked --features serde
	npm test
