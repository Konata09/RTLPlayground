.DEFAULT_GOAL := all
# Host unit-test harness for RTLPlayground firmware logic.
#
# Compiles selected firmware translation units with host gcc + AddressSanitizer,
# force-including sdcc_shim.h to erase 8051 keywords, and links them against
# mocked hardware edges (support.c). No SDCC, no flashing, no hardware.
#
#   make        build + run all tests
#   make run    run tests
#   make clean

CC       = gcc
SRCROOT  = ..
# -include shim first so __xdata/__code/__banked vanish before any firmware header.
CFLAGS   = -std=gnu11 -g -O1 -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unknown-pragmas \
           -Wno-pointer-sign \
           -DRTLP_HOST_TEST \
           -fsanitize=address,undefined -fno-omit-frame-pointer \
           -fno-sanitize-recover=all -include sdcc_shim.h -Istub -I. -I$(SRCROOT) -I$(SRCROOT)/httpd -I$(SRCROOT)/uip -I$(SRCROOT)/machine
ifeq ($(findstring clang,$(shell $(CC) --version 2>/dev/null)),)
CFLAGS  += -Wno-builtin-declaration-mismatch
endif
LDFLAGS  = -fsanitize=address,undefined

GC_LDFLAGS := $(shell printf 'int main(void){return 0;}\n' | $(CC) -x c - -o /dev/null -Wl,--gc-sections >/dev/null 2>&1 && printf '%s' '-Wl,--gc-sections')
ifeq ($(GC_LDFLAGS),)
GC_LDFLAGS := $(shell printf 'int main(void){return 0;}\n' | $(CC) -x c - -o /dev/null -Wl,-dead_strip >/dev/null 2>&1 && printf '%s' '-Wl,-dead_strip')
endif
GC_CFLAGS := $(shell printf 'int main(void){return 0;}\n' | $(CC) -Werror -ffunction-sections -fdata-sections -x c - -c -o /dev/null >/dev/null 2>&1 && printf '%s' '-ffunction-sections -fdata-sections')

BUILDDIR = build

# One binary per subsystem under test.
TESTS = $(BUILDDIR)/test_cmd_editor \
        $(BUILDDIR)/test_port_tables \
        $(BUILDDIR)/test_page_json \
        $(BUILDDIR)/test_httpd_tx \
        $(BUILDDIR)/test_tick_gate \
        $(BUILDDIR)/test_timer \
        $(BUILDDIR)/test_cpu_vlan_full \
        $(BUILDDIR)/test_cpu_vlan_restricted \
        $(BUILDDIR)/test_cpu_vlan_8372 \
        $(BUILDDIR)/test_nic_rx \
        $(BUILDDIR)/test_lacp \
        $(BUILDDIR)/test_rx_bounds

# The table tests link the register mock and one environment file; stub/
# stands in for the two headers a firmware build generates.
$(BUILDDIR)/test_rx_bounds: test_rx_bounds.c $(SRCROOT)/uip/uip_rx.h | $(BUILDDIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

TABLE_ENV = support.c hw_mock.c env_tables.c $(SRCROOT)/cmd_editor.c \
            $(SRCROOT)/rtl837x_port.c $(SRCROOT)/httpd/page_impl.c \
            $(SRCROOT)/httpd/html_out.c

all: run

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# cmd_editor.c is compiled UNMODIFIED from the firmware tree.
$(BUILDDIR)/test_cmd_editor: test_cmd_editor.c support.c $(SRCROOT)/cmd_editor.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# rtl837x_port.c and httpd/page_impl.c are compiled UNMODIFIED from the firmware tree.
$(BUILDDIR)/test_port_tables: test_port_tables.c $(TABLE_ENV) hw_mock.h | $(BUILDDIR)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@ $(LDFLAGS)

$(BUILDDIR)/test_tick_gate: test_tick_gate.c support.c $(SRCROOT)/cmd_editor.c $(SRCROOT)/timer.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# timer.c is compiled UNMODIFIED from the firmware tree.
$(BUILDDIR)/test_timer: test_timer.c support.c $(SRCROOT)/cmd_editor.c $(SRCROOT)/timer.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Exercise the production RX ring reader; only the hardware DMA edge is mocked.
# Discard unused TX functions so this RX fixture needs no TX register mocks.
$(BUILDDIR)/test_nic_rx: test_nic_rx.c $(SRCROOT)/rtl837x_nic.c $(SRCROOT)/rtl837x_nic.h | $(BUILDDIR)
	$(CC) $(CFLAGS) -ffunction-sections -fdata-sections $(filter %.c,$^) -o $@ $(LDFLAGS) $(GC_LDFLAGS)

$(BUILDDIR)/test_page_json: test_page_json.c $(TABLE_ENV) hw_mock.h | $(BUILDDIR)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@ $(LDFLAGS)

# rtl837x_lacp.c is compiled UNMODIFIED from the firmware tree.
$(BUILDDIR)/test_lacp: test_lacp.c $(SRCROOT)/rtl837x_lacp.c $(SRCROOT)/timer.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# httpd/httpd.c and uip/uip.c are compiled UNMODIFIED from the firmware tree;
# this test carries the environment below them itself.
$(BUILDDIR)/test_httpd_tx: test_httpd_tx.c $(SRCROOT)/httpd/httpd.c $(SRCROOT)/uip/uip.c $(SRCROOT)/timer.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@ $(LDFLAGS)
# the login sessions httpd.c calls into
$(BUILDDIR)/test_httpd_tx: $(SRCROOT)/sessions.c

# CPU VLAN initialization with full and reduced user-port ranges.
$(BUILDDIR)/test_cpu_vlan_restricted: CFLAGS += -DMACHINE_MAX_PORT=7
$(BUILDDIR)/test_cpu_vlan_8372: CFLAGS += -DMACHINE_MAX_PORT=7 -DMACHINE_MIN_PORT=3 -DRTLP_TEST_IS8373=0
$(BUILDDIR)/test_cpu_vlan_full $(BUILDDIR)/test_cpu_vlan_restricted $(BUILDDIR)/test_cpu_vlan_8372: test_cpu_vlan.c $(TABLE_ENV) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@ $(LDFLAGS)

run: bank-audit-unit $(TESTS) snmp snmp-horaco-profile snmp-status snmp-cli snmp-replay config-replay
	@fail=0; for t in $(TESTS); do \
		echo "=== $$t ==="; \
		$$t || fail=1; \
		echo; \
	done; \
	if [ $$fail -ne 0 ]; then echo "TESTS FAILED"; exit 1; else echo "ALL TESTS PASSED"; fi

clean:
	rm -rf $(BUILDDIR)

.PHONY: all run clean


# SNMP host benches compile the same firmware sources; listener is opt-in here.
SNMPFLAGS = $(CFLAGS) -DSNMP
SNMPENV = $(SRCROOT)/snmp.c $(SRCROOT)/snmp_control.c $(SRCROOT)/uip/uip.c $(SRCROOT)/httpd/httpd.c $(SRCROOT)/sessions.c $(SRCROOT)/timer.c
$(BUILDDIR)/test_snmp: test_snmp.c test_httpd_tx.c $(SNMPENV) | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) -DMACHINE_MAX_PORT=7 test_snmp.c $(SNMPENV) -o $@ $(LDFLAGS)

$(BUILDDIR)/test_snmp_hw: test_snmp_hw.c $(SRCROOT)/snmp_hw.c | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) test_snmp_hw.c -o $@ $(LDFLAGS)

$(BUILDDIR)/test_snmp_nine: test_snmp.c test_httpd_tx.c $(SNMPENV) | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) -DSNMP_TEST_NINE test_snmp.c $(SNMPENV) -o $@ $(LDFLAGS)

$(BUILDDIR)/test_snmp_hw_six: test_snmp_hw.c $(SRCROOT)/snmp_hw.c | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) -DSNMP_HW_SIX -DMACHINE_MIN_PORT=3 test_snmp_hw.c -o $@ $(LDFLAGS)

.PHONY: snmp snmp-unit
snmp-unit: $(BUILDDIR)/test_snmp $(BUILDDIR)/test_snmp_nine $(BUILDDIR)/test_snmp_hw $(BUILDDIR)/test_snmp_hw_six $(BUILDDIR)/test_snmp_hw_cpu_bound
	$(BUILDDIR)/test_snmp
	$(BUILDDIR)/test_snmp_nine
	$(BUILDDIR)/test_snmp_hw
	$(BUILDDIR)/test_snmp_hw selector
	$(BUILDDIR)/test_snmp_hw prebusy
	$(BUILDDIR)/test_snmp_hw link
	$(BUILDDIR)/test_snmp_hw speed
	$(BUILDDIR)/test_snmp_hw admin
	$(BUILDDIR)/test_snmp_hw_six
	$(BUILDDIR)/test_snmp_hw_cpu_bound

TRANSPORTDEPS = $(SRCROOT)/syslog.c $(SRCROOT)/dhcp.c $(SRCROOT)/uip/uip_arp.c $(SRCROOT)/snmp.h
TRANSPORTENV = $(SNMPENV) $(SRCROOT)/udp_apps.c transport_arp.c \
               transport_dhcp.c $(SRCROOT)/dns.c $(SRCROOT)/ntp.c transport_syslog.c
$(BUILDDIR)/test_snmp_transport: test_snmp_transport.c test_snmp.c test_httpd_tx.c snmp_wire_fixtures.h $(TRANSPORTENV) $(TRANSPORTDEPS) | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) -DMACHINE_MAX_PORT=7 $(GC_CFLAGS) test_snmp_transport.c $(TRANSPORTENV) -o $@ $(LDFLAGS) $(GC_LDFLAGS)
$(BUILDDIR)/test_snmp_transport_nine: test_snmp_transport.c test_snmp.c test_httpd_tx.c snmp_wire_fixtures.h $(TRANSPORTENV) $(TRANSPORTDEPS) | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) -DSNMP_TEST_NINE $(GC_CFLAGS) test_snmp_transport.c $(TRANSPORTENV) -o $@ $(LDFLAGS) $(GC_LDFLAGS)
snmp: snmp-unit $(BUILDDIR)/test_snmp_transport $(BUILDDIR)/test_snmp_transport_nine
	$(BUILDDIR)/test_snmp_transport
	$(BUILDDIR)/test_snmp_transport_nine

$(BUILDDIR)/test_snmp_horaco_profile: test_snmp_horaco_profile.c test_snmp.c test_httpd_tx.c $(SNMPENV) $(SRCROOT)/machine/HORACO_ZX_SWTGW218AS.c | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) -DMACHINE_NAME=HORACO_ZX_SWTGW218AS test_snmp_horaco_profile.c $(SNMPENV) $(SRCROOT)/machine/HORACO_ZX_SWTGW218AS.c -o $@ $(LDFLAGS)
.PHONY: snmp-horaco-profile
snmp-horaco-profile: $(BUILDDIR)/test_snmp_horaco_profile snmp-port-map
	$(BUILDDIR)/test_snmp_horaco_profile

$(BUILDDIR)/test_snmp_status_json: test_snmp_status_json.c test_page_json.c $(TABLE_ENV) $(SRCROOT)/snmp.c $(SRCROOT)/snmp_control.c | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) $(GC_CFLAGS) $(filter-out test_page_json.c,$(filter %.c,$^)) -o $@ $(LDFLAGS) $(GC_LDFLAGS)
.PHONY: snmp-status
snmp-status: $(BUILDDIR)/test_snmp_status_json
	$(BUILDDIR)/test_snmp_status_json

NODE ?= node
.PHONY: snmp-status-gui
snmp-status-gui:
	cd $(SRCROOT) && $(NODE) test/test_snmp_status_gui.cjs

$(BUILDDIR)/test_snmp_cli: test_snmp_cli.c test_snmp.c test_httpd_tx.c $(SNMPENV) | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) -DMACHINE_MAX_PORT=7 test_snmp_cli.c $(SNMPENV) -o $@ $(LDFLAGS)
.PHONY: snmp-cli
snmp-cli: $(BUILDDIR)/test_snmp_cli
	$(BUILDDIR)/test_snmp_cli

.PHONY: snmp-all snmp-replay snmp-gui
snmp-all: snmp snmp-horaco-profile snmp-status snmp-cli snmp-replay snmp-gui
snmp-replay:
	cd $(SRCROOT) && REPLAY_CC="$(CC)" python3 test/test_snmp_control_replay.py
snmp-gui:
	cd $(SRCROOT) && $(NODE) test/test_snmp_status_gui.cjs
	cd $(SRCROOT) && $(NODE) test/test_snmp_switch_gui.cjs
	cd $(SRCROOT) && $(NODE) test/test_snmp_switch_save.cjs
	cd $(SRCROOT) && $(NODE) test/test_snmp_privacy_gui.cjs
	cd $(SRCROOT) && $(NODE) test/test_snmp_full_page.cjs

$(addprefix $(BUILDDIR)/,test_snmp test_snmp_nine test_snmp_horaco_profile test_snmp_status_json test_snmp_cli test_snmp_transport test_snmp_transport_nine): snmp_setup.h $(SRCROOT)/snmp_internal.h $(SRCROOT)/snmp.h

.PHONY: config-replay
config-replay:
	cd $(SRCROOT) && CC="$(CC)" python3 test/test_config_replay.py

$(BUILDDIR)/test_snmp_port_map: test_snmp_port_map.c test_snmp.c test_httpd_tx.c $(SNMPENV) $(SRCROOT)/machine/KEEPLINK_KP_9000_6XHML_X2_2M_PCB43_V1_1.c | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) -DMACHINE_NAME=KEEPLINK_KP_9000_6XHML_X2_2M_PCB43_V1_1 $(filter-out test_snmp.c test_httpd_tx.c,$(filter %.c,$^)) -o $@ $(LDFLAGS)

$(BUILDDIR)/test_snmp_port_map_restricted: test_snmp_port_map.c test_snmp.c test_httpd_tx.c $(SNMPENV) $(SRCROOT)/machine/KEEPLINK_KP_9000_6XHML_X2_2M_PCB43_V1_1.c | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) -DMACHINE_NAME=KEEPLINK_KP_9000_6XHML_X2_2M_PCB43_V1_1 -DMACHINE_MAX_PORT=6 -DSNMP_MAP_RESTRICTED $(filter-out test_snmp.c test_httpd_tx.c,$(filter %.c,$^)) -o $@ $(LDFLAGS)

.PHONY: snmp-port-map
snmp-port-map: $(BUILDDIR)/test_snmp_port_map $(BUILDDIR)/test_snmp_port_map_restricted $(BUILDDIR)/test_snmp_port_map_cpu_bound
	$(BUILDDIR)/test_snmp_port_map
	$(BUILDDIR)/test_snmp_port_map_restricted
	$(BUILDDIR)/test_snmp_port_map_cpu_bound

$(BUILDDIR)/test_snmp_port_map_cpu_bound: test_snmp_port_map.c test_snmp.c test_httpd_tx.c $(SNMPENV) $(SRCROOT)/machine/KEEPLINK_KP_9000_6XHML_X2_2M_PCB43_V1_1.c | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) -DMACHINE_NAME=KEEPLINK_KP_9000_6XHML_X2_2M_PCB43_V1_1 -DMACHINE_MAX_PORT=CPU_LOGICAL_PORT $(filter-out test_snmp.c test_httpd_tx.c,$(filter %.c,$^)) -o $@ $(LDFLAGS)

$(BUILDDIR)/test_snmp_hw_cpu_bound: test_snmp_hw.c $(SRCROOT)/snmp_hw.c | $(BUILDDIR)
	$(CC) $(SNMPFLAGS) -DMACHINE_MAX_PORT=CPU_LOGICAL_PORT test_snmp_hw.c -o $@ $(LDFLAGS)

.PHONY: bank-audit-unit
bank-audit-unit:
	python3 test_banked_calls.py
