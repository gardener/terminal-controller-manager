# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

TOOLS_PKG_PATH             := ./hack/tools

SYSTEM_NAME                := $(shell uname -s | tr '[:upper:]' '[:lower:]')
SYSTEM_ARCH                := $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
TOOLS_BIN_DIR              := $(TOOLS_DIR)/bin/$(SYSTEM_NAME)-$(SYSTEM_ARCH)
CONTROLLER_GEN             := $(TOOLS_BIN_DIR)/controller-gen
GOSEC                      := $(TOOLS_BIN_DIR)/gosec

# default tool versions
# renovate: datasource=github-releases depName=securego/gosec
GOSEC_VERSION ?= v2.22.4

# tool versions from go.mod
CONTROLLER_GEN_VERSION ?= $(call version_gomod,sigs.k8s.io/controller-tools)

export TOOLS_BIN_DIR := $(TOOLS_BIN_DIR)
export PATH := $(abspath $(TOOLS_BIN_DIR)):$(PATH)

#########################################
# Common                                #
#########################################

# Tool targets should declare go.mod as a prerequisite, if the tool's version is managed via go modules. This causes
# make to rebuild the tool in the desired version, when go.mod is changed.
# For tools where the version is not managed via go.mod, we use a file per tool and version as an indicator for make
# whether we need to install the tool or a different version of the tool (make doesn't rerun the rule if the rule is
# changed).

# Use this "function" to add the version file as a prerequisite for the tool target: e.g.
#   $(HELM): $(call tool_version_file,$(HELM),$(HELM_VERSION))
tool_version_file = $(TOOLS_BIN_DIR)/.version_$(subst $(TOOLS_BIN_DIR)/,,$(1))_$(2)

# Use this function to get the version of a go module from go.mod
version_gomod = $(shell go list -mod=mod -f '{{ .Version }}' -m $(1))

# This target cleans up any previous version files for the given tool and creates the given version file.
# This way, we can generically determine, which version was installed without calling each and every binary explicitly.
$(TOOLS_BIN_DIR)/.version_%:
	@version_file=$@; rm -f $${version_file%_*}*
	@mkdir -p $(TOOLS_BIN_DIR)
	@touch $@

.PHONY: clean-tools-bin
clean-tools-bin:
	rm -f $(TOOLS_BIN_DIR)/{*,.version_*}

.PHONY: create-tools-bin
create-tools-bin: $(CONTROLLER_GEN) $(GOSEC)


#########################################
# Tools                                 #
#########################################

$(CONTROLLER_GEN): $(call tool_version_file,$(CONTROLLER_GEN),$(CONTROLLER_GEN_VERSION))
	go build -o $(CONTROLLER_GEN) sigs.k8s.io/controller-tools/cmd/controller-gen

$(GOSEC): $(call tool_version_file,$(GOSEC),$(GOSEC_VERSION))
	@GOSEC_VERSION=$(GOSEC_VERSION) $(TOOLS_PKG_PATH)/install-gosec.sh
