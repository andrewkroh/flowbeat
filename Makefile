BEAT_NAME=flowbeat
BEAT_PATH=github.com/andrewkroh/flowbeat
BEAT_GOPATH=$(firstword $(subst :, ,${GOPATH}))
SYSTEM_TESTS=false
TEST_ENVIRONMENT=false
ES_BEATS?=./vendor/github.com/elastic/beats
GOPACKAGES=$(shell govendor list -no-status +local)
GOBUILD_FLAGS=-i -ldflags "-X $(BEAT_PATH)/vendor/github.com/elastic/beats/libbeat/version.buildTime=$(NOW) -X $(BEAT_PATH)/vendor/github.com/elastic/beats/libbeat/version.commit=$(COMMIT_ID)"
MAGE_IMPORT_PATH=${BEAT_PATH}/vendor/github.com/magefile/mage

# Path to the libbeat Makefile
-include $(ES_BEATS)/libbeat/scripts/Makefile

# Collects all dependencies and then calls update
.PHONY: collect
collect:
