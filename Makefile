# Makefile for developing an Elastic package

# Variables
ELASTIC_PACKAGE := ~/go/bin/elastic-package
PACKAGE_NAME := first_epss
VERSION := 8.15.0

# Default target
.PHONY: all
all: build start install

# Build the package
.PHONY: build
build:
	@echo "Building the package..."
	$(ELASTIC_PACKAGE) build --change-directory packages/$(PACKAGE_NAME)

# Lint the package
.PHONY: lint
lint:
	@echo "Linting the package..."
	$(ELASTIC_PACKAGE) lint --change-directory packages/$(PACKAGE_NAME)

# Check the package
.PHONY: check
check:
	@echo "Checking the package..."
	$(ELASTIC_PACKAGE) check --change-directory packages/$(PACKAGE_NAME)

# Start the stack
.PHONY: start
start:
	@echo "Starting the elastic stack..."
	$(ELASTIC_PACKAGE) stack up --version=$(VERSION) -d

# Stop the stack
.PHONY: stop
stop:
	@echo "Stopping the elastic stack..."
	$(ELASTIC_PACKAGE) stack down

# Retstart the stack
.PHONY: restart
restart: stop start

# Install the package
.PHONY: install
install:
	@echo "Installing the package..."
	$(ELASTIC_PACKAGE) install --change-directory packages/$(PACKAGE_NAME)

# Uninstall the package
.PHONY: uninstall
uninstall:
	@echo "Installing the package..."
	$(ELASTIC_PACKAGE) uninstall --change-directory packages/$(PACKAGE_NAME)

# Reinstall the package
.PHONY: reinstall
reinstall: uninstall check build install