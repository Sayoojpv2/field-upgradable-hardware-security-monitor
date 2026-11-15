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

.PHONY: all test test-py test-c sim-rtl mutation formal synth demo experiments clean distclean venv

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

# formal verification with Yosys' built-in SAT engine: proofs, BMC, covers, planted-bug check
formal: .venv/.installed
	$(PY) scripts/run_formal.py

synth: .venv/.installed
	$(PY) scripts/synth.py

# ---------------------------------------------------------------- demonstration
CORPUS := build/traces/corpus.csv
$(CORPUS): tools/trace_validator.py tools/hsm_common.py .venv/.installed
	$(PY) tools/trace_validator.py gen --out $@

# ten-step walkthrough: RTL decisions, release gate, hardware validation, device run with power loss
demo: $(DEMOBIN) $(PKGS) $(CORPUS)
	$(PY) scripts/demo.py --fw $(DEMOBIN)

experiments: sim-rtl synth
	$(PY) scripts/run_experiments.py

# ---------------------------------------------------------------- housekeeping
clean:
	$(PYTHON) -c "import shutil; [shutil.rmtree(d, ignore_errors=True) for d in ('build', '.pytest_cache')]"

distclean: clean
	$(PYTHON) -c "import shutil; shutil.rmtree('.venv', ignore_errors=True)"
