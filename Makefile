# Field-upgradeable hardware security monitor - build, test, synthesis and demo.
# Run from the repository root with a POSIX shell (Git Bash / MSYS2 on Windows, any shell on Linux).
# Machine-specific tool locations go in local.mk (see local.mk.example); defaults use PATH.

-include local.mk

ifeq ($(origin CC),default)
CC := gcc
endif
IVERILOG ?= iverilog
VVP      ?= vvp
YOSYS    ?= yowasp-yosys
PYTHON   ?= python3
RISCV_CC ?= riscv64-unknown-elf-gcc
export IVERILOG VVP YOSYS RISCV_CC

ifeq ($(OS),Windows_NT)
PY  := .venv/Scripts/python.exe
EXE := .exe
else
PY  := .venv/bin/python
EXE :=
endif

CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror
INC     := -Ifirmware/include -Ifirmware/third_party/monocypher
GEN     := build/gen/device_config.c
CORE_C  := firmware/src/policy_pkg.c firmware/src/policy_manager.c firmware/src/pstore.c \
           firmware/third_party/monocypher/monocypher.c firmware/third_party/monocypher/monocypher-ed25519.c
FW_HDRS := $(wildcard firmware/include/*.h)
PKGS    := build/pkgs/.stamp
TESTBIN := build/fw/test_firmware$(EXE)
DEMOBIN := build/fw/fw_demo$(EXE)

.PHONY: all test test-py test-c sim-rtl mutation synth demo experiments clean distclean venv

all: test

test: test-py test-c sim-rtl mutation
	@echo "ALL TESTS PASSED"

# ---------------------------------------------------------------- Python environment
.venv/.installed: requirements.txt
	$(PYTHON) -m venv $(VENV_FLAGS) .venv
	$(PY) -m pip install -q -r requirements.txt
	@touch $@
venv: .venv/.installed

# ---------------------------------------------------------------- keys, device config, packages
$(GEN): .venv/.installed tools/policy_signer.py
	$(PY) tools/policy_signer.py keygen --keys build/keys --c-out $@

$(PKGS): $(GEN) $(wildcard examples/*.json examples/*/*.json) $(wildcard tools/*.py)
	$(PY) tools/policy_signer.py testset --keys build/keys --examples examples --out build/pkgs
	@touch $@

# ---------------------------------------------------------------- tests
test-py: .venv/.installed
	$(PY) -m pytest -q tests

$(TESTBIN): $(CORE_C) firmware/src/hal_host.c firmware/tests/test_firmware.c $(GEN) $(FW_HDRS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INC) -o $@ $(filter %.c,$^)

$(DEMOBIN): $(CORE_C) firmware/src/hal_host.c firmware/src/demo_main.c $(GEN) $(FW_HDRS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INC) -o $@ $(filter %.c,$^)

test-c: $(TESTBIN) $(PKGS)
	@mkdir -p build/results
	$(TESTBIN) build/pkgs build/fw/mmio_tests.log build/results/fault_injection.json

sim-rtl: test-c
	$(PY) scripts/run_rtl.py --replay build/fw/mmio_tests.log

# plant known security bugs in a copy of the RTL; every one must be caught
mutation: sim-rtl
	$(PY) scripts/mutation_check.py

synth: .venv/.installed
	$(PY) scripts/synth.py

# ---------------------------------------------------------------- demonstration
CORPUS := build/traces/corpus.csv
$(CORPUS): tools/trace_validator.py tools/hsm_common.py .venv/.installed
	$(PY) tools/trace_validator.py gen --out $@

GATE = $(PY) tools/trace_validator.py compare --trace $(CORPUS)
demo: $(DEMOBIN) $(PKGS) $(CORPUS)
	@echo "== [A] Offline release gate: trace validation before signing (exit 1 = not recommended)"
	$(GATE) --baseline examples/policy_v1.json --candidate examples/policy_v2.json --report build/reports/policy_v2.md
	$(GATE) --baseline examples/policy_v2.json --candidate examples/policy_v3.json --report build/reports/policy_v3.md
	$(GATE) --baseline examples/policy_v3.json --candidate examples/policy_v4.json --report build/reports/policy_v4.md
	$(GATE) --baseline examples/policy_v1.json --candidate examples/candidates/cand_v2_overbroad.json --report build/reports/cand_v2_overbroad.md || echo ">> gate refused cand_v2_overbroad (expected)"
	$(GATE) --baseline examples/policy_v4.json --candidate examples/candidates/cand_v5_dma_reopen.json --report build/reports/cand_v5_dma_reopen.md || echo ">> gate refused cand_v5_dma_reopen (expected)"
	@echo "== [B] Device: firmware + host hardware model"
	$(DEMOBIN) build/pkgs build/fw/mmio_demo.log
	@echo "== [C] The same register traffic replayed into the RTL"
	$(PY) scripts/run_rtl.py --only-replay --replay build/fw/mmio_demo.log

experiments: sim-rtl synth
	$(PY) scripts/run_experiments.py

# ---------------------------------------------------------------- housekeeping
clean:
	$(PYTHON) -c "import shutil; shutil.rmtree('build', ignore_errors=True)"

distclean: clean
	$(PYTHON) -c "import shutil; shutil.rmtree('.venv', ignore_errors=True)"
