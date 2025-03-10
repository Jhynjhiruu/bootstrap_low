TARGET := build/bootstrap.bin
ELF := $(TARGET:.bin=.elf)

DEBUG ?= 1

PYTHON ?= python3
ELFPATCH := $(PYTHON) tools/elfpatch.py

IQUECRYPT ?= iquecrypt
KEY ?= 00000000000000000000000000000000
IV ?= 00000000000000000000000000000000
APP ?= btstrplo.app

PREFIX := mips64-elf-

COMPILER_PATH ?= $(N64_INST)/bin
CROSS ?= $(COMPILER_PATH)/$(PREFIX)

CC := $(CROSS)gcc
AS := $(CROSS)as
LD := $(CROSS)ld
AR := $(CROSS)ar

RANLIB  := $(CROSS)ranlib
OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump
STRIP   := $(CROSS)strip

#LIBGCC_DIR ?= $(dir $(shell $(CC) --print-libgcc-file-name))

SRC_DIRS := $(shell /usr/bin/find src -type d)

C_FILES := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))
S_FILES := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.s))
O_FILES := $(foreach f,$(C_FILES:.c=.o),build/$f) \
           $(foreach f,$(S_FILES:.s=.o),build/$f)

LIB_DIR := build/lib

ifeq ($(DEBUG),1)
	LIBULTRA_VERSION := ultra_d
	DEBUG_FLAG := -DDEBUG
else
	LIBULTRA_VERSION := ultra
	DEBUG_FLAG := -DNODEBUG
endif

INC := -I include -I include/PR -I include/sys -I src
LIBDIRS := -L $(LIB_DIR)
LIB := -l$(LIBULTRA_VERSION) -lgcc
LIBS := $(LIB_DIR)/lib$(LIBULTRA_VERSION).a $(LIB_DIR)/libgcc.a
CFLAGS := $(INC) -D_MIPS_SZLONG=32 -D_LANGUAGE_C -DBBPLAYER $(DEBUG_FLAG) -nostdinc -fno-builtin -fno-PIC -mno-abicalls -G 0 -mabi=32 -mgp32 -Wall -Wa,-Iinclude -march=vr4300 -mtune=vr4300 -ffunction-sections -fdata-sections -g -ffile-prefix-map="$(CURDIR)"= -Os -Wall -Werror -Wno-error=deprecated-declarations -fdiagnostics-color=always
ASFLAGS := $(INC) -D_MIPS_SZLONG=32 -D_LANGUAGE_ASSEMBLY -DBBPLAYER $(DEBUG_FLAG) -nostdinc -fno-PIC -mno-abicalls -G 0 -mabi=32 -march=vr4300 -mtune=vr4300 -Wa,-Iinclude

$(shell mkdir -p build $(foreach dir,$(SRC_DIRS) lib,build/$(dir)))

.PHONY: all clean
.SECONDARY:

all: $(TARGET)

clean:
	$(RM) -r build

$(TARGET): $(ELF)
	$(OBJCOPY) -O binary $< $(@:.bin=.tmp)
	dd if=$(@:.bin=.tmp) of=$@ bs=16K conv=sync status=none
	@$(RM) -r $(@:.bin=.tmp)

app: $(TARGET)
	$(IQUECRYPT) encrypt -app $(TARGET) -key $(KEY) -iv $(IV) -o $(APP)

$(LIB_DIR)/lib%: lib/lib%.a
	$(shell mkdir -p $@)
	$(AR) x --output=$@ $<

$(LIB_DIR)/lib%.a: $(LIB_DIR)/lib%
	$(ELFPATCH) $(wildcard $</*.o)
	@$(STRIP) -N dummy_symbol_ $(wildcard $</*.o)
	$(AR) r $@ $(wildcard $</*.o)
	$(RANLIB) $@

$(ELF): $(C_FILES) $(S_FILES) $(LIBS) | $(O_FILES)
	$(LD) -T bootstrap.lcf -o $@ $| $(LIBDIRS) -Map $(@:.elf=.map) $(LIB) --no-warn-mismatch

build/src/%.o: src/%.s
	$(CC) -x assembler-with-cpp $(ASFLAGS) -c $< -o $@
	@$(OBJDUMP) -drz $@ > $(@:.o=.s)

build/src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@
	@$(OBJDUMP) -drz $@ > $(@:.o=.s)
