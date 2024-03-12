#=======================================================================
# UCB VLSI FLOW: Makefile for riscv-bmarks
#-----------------------------------------------------------------------
# Yunsup Lee (yunsup@cs.berkeley.edu)
#

XLEN ?= 32

default: all

src_dir = .

instname = riscv-bmarks
instbasedir = $(UCB_VLSI_HOME)/install

#--------------------------------------------------------------------
# Sources
#--------------------------------------------------------------------

bmarks_mt = \
	mm \
	mt-vvadd \
	mt-matmul \

bmarks_st = \
	median \
	qsort \
	rsort \
	towers \
	vvadd \
	multiply \
	dhrystone \
	spmv \
	pmp \

bmarks := $(bmarks_st) # $(bmarks_mt)

#--------------------------------------------------------------------
# Build rules
#--------------------------------------------------------------------

RISCV_PREFIX ?= riscv$(XLEN)-unknown-elf-
RISCV_GCC ?= $(RISCV_PREFIX)gcc
RISCV_OBJCOPY ?= $(RISCV_PREFIX)objcopy
RISCV_GCC_OPTS ?= -DPREALLOCATE=1 -mcmodel=medany -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf
RISCV_S51_GCC_OPTS ?= -DPREALLOCATE=1 -march=rv32im -mabi=ilp32 -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf -nostdlib -nostartfiles -fno-builtin -ffreestanding
RISCV_LINK ?= $(RISCV_GCC) -T $(src_dir)/common/test.ld $(incs)
RISCV_LINK_OPTS ?= -static -nostdlib -nostartfiles -lm -lgcc -T $(src_dir)/common/test.ld
RISCV_S51_LINK_OPTS ?= -static -nostdlib -nostartfiles -lm -lgcc -T ./linker.ld
RISCV_OBJDUMP ?= $(RISCV_PREFIX)objdump --disassemble-all --disassemble-zeroes --section=.text --section=.text.startup --section=.text.init --section=.data
RISCV_SIM ?= spike --isa=rv$(XLEN)gc

incs  += -I$(src_dir)/../env -I$(src_dir)/common $(addprefix -I$(src_dir)/, $(bmarks))
objs  :=

define compile_template
$(1).riscv: $(wildcard $(src_dir)/$(1)/*) $(wildcard $(src_dir)/common/*)
	$$(RISCV_GCC) $$(incs) $$(RISCV_GCC_OPTS) -o $$@ $(wildcard $(src_dir)/$(1)/*.c) $(wildcard $(src_dir)/common/*.c) $(wildcard $(src_dir)/common/*.S) $$(RISCV_LINK_OPTS)
# object files named .elf consistent with examples
$(1).elf: $(wildcard $(src_dir)/$(1)/*) $(src_dir)/common/syscalls_s51.c
	$$(RISCV_GCC) $$(incs) $$(RISCV_S51_GCC_OPTS) -o $$@ $(wildcard $(src_dir)/$(1)/*.c) $(src_dir)/common/syscalls_s51.c $$(RISCV_S51_LINK_OPTS) ../../../examples/c/init.S -Wl,-Map=$(1).map
endef

$(foreach bmark,$(bmarks),$(eval $(call compile_template,$(bmark))))

#------------------------------------------------------------
# Build and run benchmarks on riscv simulator

bmarks_riscv_bin  = $(addsuffix .riscv,  $(bmarks))
bmarks_riscv_dump = $(addsuffix .riscv.dump, $(bmarks))
bmarks_riscv_out  = $(addsuffix .riscv.out,  $(bmarks))

$(bmarks_riscv_dump): %.riscv.dump: %.riscv
	$(RISCV_OBJDUMP) $< > $@

$(bmarks_riscv_out): %.riscv.out: %.riscv
	$(RISCV_SIM) $< > $@

riscv: $(bmarks_riscv_dump)
run: $(bmarks_riscv_out)

junk += $(bmarks_riscv_bin) $(bmarks_riscv_dump) $(bmarks_riscv_hex) $(bmarks_riscv_out)

#------------------------------------------------------------
# Build and run benchmarks on s51 simulator with rv51 emulator

%.bin: %.elf
	${RISCV_OBJCOPY} -S -O binary $< $@
	chmod -x $@

%.combined.bin: ../../../src/rv51.bin %.bin
	cat $^ > $@

.PHONY: ../../../src/rv51.bin
../../../src/rv51.bin:
	make -C ../../../src

%.ihx: %.bin
	sdobjcopy -I binary -O ihex $< $@

%.sim: %.combined.ihx
	s51 -G -t 8052 -X 12M -b -S out=- -e "break $(shell grep exec_ebreak: ../../main.lst | sed 's/\s\+\([0-9A-F]\+\).*/0x\1/g')" -e run $<

bmarks_s51_bin  = $(addsuffix .elf,  $(bmarks_st))
bmarks_s51_combined_bin = $(addsuffix .combined.bin, $(bmarks_st))
bmarks_s51_combined_ihx = $(addsuffix .combined.ihx, $(bmarks_st))

junk += $(bmarks_s51_bin) $(bmarks_s51_combined_bin) $(bmarks_s51_combined_ihx)


# once simulation is begun you can activate the console by adding -c /dev/tty to the command line
# halting s51 on a specific RISCV instruction:
# 0x66 is fetch_instruction and dptr will reflect the RISCV program counter
# rv_code (a symbol within 8051 main.S) + the RISCV offset gives you DPTR
# e.g. rv_code == 0x1208, main (in RISCV) = b8, we want 0x12c0:
# break 0x000066 if ((dph==0x12)&&(dpl==0xc0))
# or to stop at "start" before we run anything at all
# break 0x000066 if ((dph==0x12)&&(dpl==0x08))


#------------------------------------------------------------
# Default

all: riscv

#------------------------------------------------------------
# Install

date_suffix = $(shell date +%Y-%m-%d_%H-%M)
install_dir = $(instbasedir)/$(instname)-$(date_suffix)
latest_install = $(shell ls -1 -d $(instbasedir)/$(instname)* | tail -n 1)

install:
	mkdir $(install_dir)
	cp -r $(bmarks_riscv_bin) $(bmarks_riscv_dump) $(install_dir)

install-link:
	rm -rf $(instbasedir)/$(instname)
	ln -s $(latest_install) $(instbasedir)/$(instname)

#------------------------------------------------------------
# Clean up

clean:
	rm -rf $(objs) $(junk)
