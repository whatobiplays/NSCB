TARGET := nscb_split_readback
BUILD := build
SOURCES := source
INCLUDES := include

SPLIT_PATH ?= /nscb-qualification/Game.nsp
EXPECTED_SIZE ?=
EXPECTED_SHA256 ?=

ifeq ($(strip $(EXPECTED_SIZE)),)
$(error set EXPECTED_SIZE to the source byte length)
endif
ifeq ($(strip $(EXPECTED_SHA256)),)
$(error set EXPECTED_SHA256 to the source SHA-256)
endif

include $(DEVKITPRO)/libnx/switch_rules

CFLAGS += -Wall -Wextra \
	-DSPLIT_PATH=\"$(SPLIT_PATH)\" \
	-DEXPECTED_SIZE=$(EXPECTED_SIZE)ULL \
	-DEXPECTED_SHA256=\"$(EXPECTED_SHA256)\" \
	-I$(PORTLIBS)/include
LIBS += -L$(PORTLIBS)/lib -lmbedcrypto
