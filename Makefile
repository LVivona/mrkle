ROOT_DIR := $(shell pwd)
CARGO_DIR := $(ROOT_DIR)/mrkle
CARGO_TARGET_DIR := $(CARGO_DIR)/docs
CARGO_KATEX_HEADER := $(CARGO_TARGET_DIR)/katex.html

PYTHON_DIR := $(ROOT_DIR)/bindings/python
SPHINX_SOURCE := $(PYTHON_DIR)/docs
SPHINX_BUILD := $(SPHINX_SOURCE)/_build

$(CARGO_TARGET_DIR):
	mkdir -p $(CARGO_TARGET_DIR)

$(CARGO_KATEX_HEADER):
	@echo "Error: KaTeX header file not found at $(CARGO_KATEX_HEADER)"
	@exit 1

define cargo_docs
	cd $(CARGO_DIR) && \
	RUSTDOCFLAGS="--html-in-header=$(CARGO_KATEX_HEADER)" cargo doc --no-deps --target-dir=$(CARGO_TARGET_DIR) $(1)
endef

mrkle $(PYTHON_DIR):
	cargo build --release -p mrkle
	maturin develop --release -m $(PYTHON_DIR)/Cargo.toml

cargo-docs: $(CARGO_TARGET_DIR) $(CARGO_KATEX_HEADER)
	$(call cargo_docs)

cargo-docs-open: $(CARGO_TARGET_DIR) $(CARGO_KATEX_HEADER)
	$(call cargo_docs,--open)

sphinx:
	sphinx-build $(SPHINX_SOURCE) $(SPHINX_BUILD)

sphinx-open: sphinx
	python -m http.server -d $(SPHINX_BUILD)

clean:
	cargo clean

.PHONY: cargo-docs cargo-docs-open mrkle sphinx sphinx-open clean
