BEAT_NAME=flowbeat
BEAT_PATH=github.com/andrewkroh/flowbeat
BEAT_GOPATH=$(firstword $(subst :, ,${GOPATH}))
BEAT_VERSION=0.1.0
SYSTEM_TESTS=false
TEST_ENVIRONMENT=false
ES_BEATS?=.elastic-beats
GOPACKAGES=$(shell govendor list -no-status +local)
GOBUILD_FLAGS=-i -ldflags "-X $(BEAT_PATH)/vendor/github.com/elastic/beats/libbeat/version.buildTime=$(NOW) -X $(BEAT_PATH)/vendor/github.com/elastic/beats/libbeat/version.commit=$(COMMIT_ID)"
MAGE_IMPORT_PATH=${BEAT_PATH}/vendor/github.com/magefile/mage
CHECK_HEADERS_DISABLED=true

# Path to the libbeat Makefile
-include $(ES_BEATS)/libbeat/scripts/Makefile

# Collects all dependencies and then calls update
.PHONY: collect
collect:

.PHONY: ensure
ensure:
	dep ensure
	mkdir -p vendor/github.com/elastic/beats/libbeat/scripts
	cp -Rp $$GOPATH/src/github.com/elastic/beats/libbeat/scripts/ vendor/github.com/elastic/beats/libbeat/scripts/
	mkdir -p vendor/github.com/elastic/beats/libbeat/tests/system
	cp $$GOPATH/src/github.com/elastic/beats/libbeat/tests/system/requirements.txt vendor/github.com/elastic/beats/libbeat/tests/system/
