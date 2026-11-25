.SUFFIXES:

ifeq ($(strip $(DEVKITPRO)),)
$(error Set DEVKITPRO to the devkitPro installation directory)
endif

TOPDIR ?= $(CURDIR)
include $(DEVKITPRO)/libnx/switch_rules

TARGET := nscb_split_readback
BUILD := build
SOURCES := source
DATA :=
INCLUDES := include
APP_TITLE := NSCB Split readback checker
APP_AUTHOR := NSCB
APP_VERSION := 1.0.0

SPLIT_PATH ?= /nscb-qualification/qualification-source.nsp
EXPECTED_SIZE ?=
EXPECTED_SHA256 ?=
SPLIT_CONFIG_HEADER := $(TOPDIR)/$(BUILD)/qualification_config.h

ifneq ($(strip $(filter clean,$(MAKECMDGOALS))),clean)
REQUIRES_SPLIT_CONFIG := yes
else ifneq ($(strip $(filter-out clean,$(MAKECMDGOALS))),)
REQUIRES_SPLIT_CONFIG := yes
endif

ifneq ($(REQUIRES_SPLIT_CONFIG),)
ifeq ($(strip $(EXPECTED_SIZE)),)
$(error Set EXPECTED_SIZE to the original source byte length)
endif
ifeq ($(strip $(EXPECTED_SHA256)),)
$(error Set EXPECTED_SHA256 to the original source SHA-256)
endif
endif

ARCH := -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE
CFLAGS := -g -Wall -Wextra -O2 -ffunction-sections -fdata-sections $(ARCH)
CFLAGS += $(INCLUDE) -D__SWITCH__
CXXFLAGS := $(CFLAGS) -fno-rtti -fno-exceptions
ASFLAGS := -g $(ARCH)
LDFLAGS = -specs=$(DEVKITPRO)/libnx/switch.specs -g $(ARCH) -Wl,-Map,$(notdir $*.map)
LIBS := -lmbedcrypto -lnx
LIBDIRS := $(PORTLIBS) $(LIBNX)

ifneq ($(BUILD),$(notdir $(CURDIR)))
export OUTPUT := $(CURDIR)/$(TARGET)
export TOPDIR := $(CURDIR)
export VPATH := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR := $(CURDIR)/$(BUILD)

CFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))
BINFILES := $(foreach dir,$(DATA),$(notdir $(wildcard $(dir)/*.*)))

ifeq ($(strip $(CPPFILES)),)
export LD := $(CC)
else
export LD := $(CXX)
endif

export OFILES_BIN := $(addsuffix .o,$(BINFILES))
export OFILES_SRC := $(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)
export OFILES := $(OFILES_BIN) $(OFILES_SRC)
export HFILES_BIN := $(addsuffix .h,$(subst .,_,$(BINFILES)))
export INCLUDE := $(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
	$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
	-I$(CURDIR)/$(BUILD)
export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib)

.PHONY: all clean $(BUILD)
all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

clean:
	@echo clean ...
	@rm -fr $(BUILD) $(TARGET).nro $(TARGET).nacp $(TARGET).elf
else
.PHONY: all FORCE_CONFIG
DEPENDS := $(OFILES:.o=.d)

all: $(OUTPUT).nro
$(OUTPUT).nro: $(OUTPUT).elf $(OUTPUT).nacp
$(OUTPUT).elf: $(OFILES)
$(OFILES_SRC): $(HFILES_BIN) $(SPLIT_CONFIG_HEADER)

FORCE_CONFIG:
$(SPLIT_CONFIG_HEADER): FORCE_CONFIG
	@mkdir -p "$(@D)"
	@printf '%s\n' \
		'#define SPLIT_PATH "$(SPLIT_PATH)"' \
		'#define EXPECTED_SIZE $(EXPECTED_SIZE)ULL' \
		'#define EXPECTED_SHA256 "$(EXPECTED_SHA256)"' > "$@.tmp"
	@if ! cmp -s "$@.tmp" "$@"; then mv "$@.tmp" "$@"; else rm -f "$@.tmp"; fi

-include $(DEPENDS)
endif
