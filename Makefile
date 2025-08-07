# Define variables
ROOT_DIR := $(shell pwd)
AGENT_DIR := $(ROOT_DIR)/wormhole-agent
CORE_DIR := $(ROOT_DIR)/wormhole-core
GUI_DIR := $(ROOT_DIR)/wormhole-gui
COMPILED_AGENT_DIR := $(ROOT_DIR)/agents
DATA_DIR := $(ROOT_DIR)/appData

.PHONY: all
all: build-agent-ios build-agent-macos install-node-gui setup-venv

# Install Node.js dependencies (if not already installed)
install-node-agent:
	cd $(AGENT_DIR); \
	if [ ! -d "node_modules/" ]; then \
		npm install; \
	fi

# Build the agent (including copying template files if needed)
build-agent-ios: install-node-agent
	
	cd $(AGENT_DIR); \
	if [ ! -e "src/common/hooking/hooking.ts" ]; then \
		cp src/common/hooking/hooking.template.ts src/common/hooking/hooking.ts; \
	fi; \
	npm run build-ios || exit 1;

# Build the agent (including copying template files if needed)
build-agent-macos: install-node-agent
	
	cd $(AGENT_DIR); \
	if [ ! -e "src/common/hooking/hooking.ts" ]; then \
		cp src/common/hooking/hooking.template.ts src/common/hooking/hooking.ts; \
	fi; \
	npm run build-macos || exit 1;


# Install Node.js dependencies (if not already installed)
install-node-gui:
	cd $(GUI_DIR); \
	if [ ! -d "node_modules/" ]; then \
		npm install; \
	fi

# Set up the Python virtual environment
setup-venv:
	if [ ! -d "venv" ]; then \
		python3 -m venv ./venv/; \
		. venv/bin/activate; \
		pip install --upgrade pip; \
		pip install -r $(CORE_DIR)/requirements.txt; \
		pip install -r requirements.txt ;\
	fi

# Install wormhole-core if required
.PHONY: reinstall-core
reinstall-core:
	. venv/bin/activate; \
	pip uninstall wormhole-core -y; \
	rm -rf $(CORE_DIR)/build; \
	rm -rf $(CORE_DIR)/wormhole_core.egg-info; \
	pip install $(CORE_DIR)/; \


# Run the Python web server
.PHONY: run-server
run-server: setup-venv
	. venv/bin/activate; \
	python3 $(ROOT_DIR)/web.py


# Run the trace script
.PHONY: run-trace
run-trace: setup-venv
	. venv/bin/activate; \
	python3 $(ROOT_DIR)/scripts/trace.py

# Run the trace script
.PHONY: run-dump
run-dump: setup-venv
	. venv/bin/activate; \
	python3 $(ROOT_DIR)/scripts/dump_unencrypted_ipa.py

# Clean up build artifacts
.PHONY: clean
clean:
	rm -rf $(AGENT_DIR)/node_modules
	rm -rf $(AGENT_DIR)/package-lock.json
	rm -rf $(COMPILED_AGENT_DIR)/*
	rm -rf venv
	rm -rf $(CORE_DIR)/build
	rm -rf $(CORE_DIR)/wormhole_core.egg-info
	rm -rf $(DATA_DIR)/*

.PHONY: run-gui
run-gui: install-node-gui
	cd $(GUI_DIR) && npm run serve

# Run the Python web server
.PHONY: run
run:
	@$(MAKE) -j 2 run-server run-gui