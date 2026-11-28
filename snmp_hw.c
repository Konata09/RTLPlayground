#include "rtl837x_common.h"
#include "rtl837x_sfr.h"
#include "rtl837x_regs.h"
#include "phy.h"
#include "machine.h"
#include "snmp_hw.h"

#pragma codeseg BANK4
#pragma constseg BANK4

extern __code const struct machine machine;
/* Set when a statistics request timed out: its selector may still be pending.
 * Cleared only after the SFR engine and STAT_GET are observed idle. */
static __xdata uint8_t fault;

void snmp_hw_init(void) __banked
{
	/* Establish the recovery state explicitly, independent of the CRT. */
	fault = 0;
}

/* The host edge models SFR command completion, including a stuck engine. */
#ifdef RTLP_HOST_TEST
extern void snmp_hw_command(uint16_t reg, uint8_t command);
extern bool snmp_hw_sfp_read(uint8_t sfp, uint8_t reg, uint16_t *raw);
#endif
static bool access(uint16_t reg, __xdata uint8_t command)
{
	uint16_t budget = 512;
	if (SFR_EXEC_STATUS)
		return false;
#ifdef RTLP_HOST_TEST
	snmp_hw_command(reg, command);
#else
	SFR_REG_ADDR_U16 = reg;
	SFR_EXEC_GO = command;
#endif
	do {
		if (!SFR_EXEC_STATUS)
			return true;
	} while (--budget);
	return false;
}

static void copy_word(__xdata uint8_t *__xdata value)
{
	value[0] = SFR_DATA_24;
	value[1] = SFR_DATA_16;
	value[2] = SFR_DATA_8;
	value[3] = SFR_DATA_0;
}

static bool user_port(uint8_t port)
{
#if MACHINE_MIN_PORT >= CPU_LOGICAL_PORT
	return false;
#elif MACHINE_MAX_PORT >= CPU_LOGICAL_PORT
	/* Clip an unusual profile reaching the CPU without redundant comparisons. */
	return (uint8_t)(port - MACHINE_MIN_PORT) < CPU_LOGICAL_PORT - MACHINE_MIN_PORT;
#else
	/* The profile range already excludes the CPU. */
	return MACHINE_PORT_VALID(port);
#endif
}

/* A statistics request may start only when no command is in flight and, after
 * a timeout, STAT_GET proves its selector finished. Read-only probe, no reset. */
static bool stat_ready(void)
{
	if (SFR_EXEC_STATUS) {
		fault = 1;
		return false;
	}
	if (fault) {
		fault = 0;
		/* STAT_GET bit 0 is the selector's busy bit. */
		fault = !access(RTL837X_STAT_GET, SFR_EXEC_READ_REG) || (SFR_DATA_0 & 1);
	}
	return !fault;
}

/* Fill tmp[4..7] (and tmp[0..3] when both halves are read) from one snapshot. */
static bool stat_words(uint8_t port, __xdata uint8_t selector, __xdata bool high,
		       __xdata bool low, __xdata uint8_t *__xdata tmp)
{
	uint8_t budget = 32;
	SFR_DATA_24 = 0;
	SFR_DATA_16 = 0;
	SFR_DATA_8 = selector >> 3;
	SFR_DATA_0 = (selector << 5) | (port << 1) | 1;
	if (!access(RTL837X_STAT_GET, SFR_EXEC_WRITE_REG))
		return false;
	do {
		if (!access(RTL837X_STAT_GET, SFR_EXEC_READ_REG))
			return false;
		if (!(SFR_DATA_0 & 1)) {
			if (high) {
				if (!access(RTL837X_STAT_V_HIGH, SFR_EXEC_READ_REG))
					return false;
				copy_word(low ? tmp : tmp + 4);
			}
			if (low) {
				if (!access(RTL837X_STAT_V_LOW, SFR_EXEC_READ_REG))
					return false;
				copy_word(tmp + 4);
			}
			return true;
		}
	} while (--budget);
	return false;
}

/* The caller's counter changes only after the whole snapshot was read. */
static bool stat_get(uint8_t port, __xdata uint8_t selector, __xdata bool high,
		     __xdata bool low, __xdata struct snmp_counter *__xdata value)
{
	__xdata uint8_t tmp[8];
	uint8_t i;
	if (!user_port(port) || !stat_ready())
		return false;
	for (i = 0; i < 4; i++)
		tmp[i] = 0;
	if (!stat_words(port, selector, high, low, tmp)) {
		fault = 1;
		return false;
	}
	for (i = 0; i < 8; i++)
		value->bytes[i] = tmp[i];
	return true;
}

bool snmp_hw_counter(uint8_t port, __xdata uint8_t selector,
		     __xdata struct snmp_counter *__xdata value) __banked
{
	/* Only the eight native 64-bit interface counters are defined here. */
	return selector <= 7 && stat_get(port, selector, true, true, value);
}

bool snmp_hw_counter32(uint8_t port, __xdata uint8_t selector, __xdata bool high,
		       __xdata struct snmp_counter *__xdata value) __banked
{
	/* Selector 48 is the RX/TX error pair; a 32-bit word is zero-extended. */
	return selector == 48 && stat_get(port, selector, high, !high, value);
}

/* Copper admin state is PHY MMD31.a610 bit 11 (power down); SFP has no switch. */
bool snmp_hw_admin(uint8_t port, __xdata uint8_t *__xdata state) __banked
{
	if (!user_port(port))
		return false;
	if (machine.is_sfp[port]) {
		*state = 1;
		return true;
	}
	/* SMI setup overwrites SFR data, so check idle before touching anything. */
	if (!stat_ready())
		return false;
	SFR_SMI_REG_U16 = 0xa610;
	SFR_SMI_PHY = port;
	SFR_SMI_DEV = (uint8_t)((31U << 3) | 2U);
	if (!access(0xa610, SFR_EXEC_READ_SMI))
		return false;
	*state = (SFR_DATA_8 & 0x08) ? 2 : 1;
	return true;
}

bool snmp_hw_link(uint8_t port, __xdata uint32_t *__xdata value) __banked
{
	if (!user_port(port) || !stat_ready() ||
	    !access(RTL837X_REG_LINKS_STS, SFR_EXEC_READ_REG))
		return false;
	/* GUI: sfr_data[(port / 8) + 1], i.e. A5 for MAC0..7, A6 for MAC8.
	 * A4/A7 are not the user-port bitmap; do not expose their bits as link. */
	*value = SFR_DATA_16 | ((uint16_t)SFR_DATA_8 << 8);
	return true;
}

/* Return zero when no negotiated speed is available; never infer a capability. */
bool snmp_hw_speed(uint8_t port, __xdata uint16_t *__xdata mbps) __banked
{
	__xdata uint32_t links;
	__xdata uint8_t code;
	if (!snmp_hw_link(port, &links))
		return false;
	*mbps = 0;
	/* snmp_hw_link() has already validated the MAC port range 0..8 and returns a 16-bit mask. */
	if (!((uint16_t)links & ((uint16_t)1 << port)))
		return true;
	if (!access(port < 8 ? RTL837X_REG_LINKS : RTL837X_REG_LINKS_89, SFR_EXEC_READ_REG))
		return false;
	switch ((port & 7) >> 1) {
	case 0:
		code = SFR_DATA_0;
		break;
	case 1:
		code = SFR_DATA_8;
		break;
	case 2:
		code = SFR_DATA_16;
		break;
	default:
		code = SFR_DATA_24;
		break;
	}
	code = (port & 1) ? code >> 4 : code & 15;
	switch (code) {
	case 0:
		*mbps = 10;
		break;
	case 1:
		*mbps = 100;
		break;
	case 2:
		*mbps = 1000;
		break;
	case 4:
		*mbps = 10000;
		break;
	case 5:
		*mbps = 2500;
		break;
	case 6:
		*mbps = 5000;
		break;
	default:
		break;
	}
	return true;
}

bool snmp_hw_mtu(uint8_t port, __xdata uint16_t *__xdata mtu) __banked
{
	if (!user_port(port) || !stat_ready() ||
	    !access(RTL8373_REG_MAC_L2_PORT_MAX_LEN + ((uint16_t)port << 8), SFR_EXEC_READ_REG))
		return false;
	*mtu = (((uint16_t)SFR_DATA_8 << 8) | SFR_DATA_0) & 0x3fff;
	return true;
}

/* dot3StatsDuplexStatus: 1 unknown, 2 halfDuplex, 3 fullDuplex. */
bool snmp_hw_duplex(uint8_t port, __xdata uint8_t *__xdata duplex) __banked
{
	__xdata uint16_t mbps;
	if (!snmp_hw_speed(port, &mbps))
		return false;
	if (!mbps) {
		*duplex = 1;
		return true;
	}
	if (machine.is_sfp[port] || mbps >= 2500) {
		*duplex = 3;
		return true;
	}
	if (!stat_ready())
		return false;
	SFR_SMI_REG_U16 = PHY_MMD31_PHYSR;
	SFR_SMI_PHY = port;
	SFR_SMI_DEV = (uint8_t)((31U << 3) | 2U);
	if (!access(PHY_MMD31_PHYSR, SFR_EXEC_READ_SMI))
		return false;
	*duplex = (SFR_DATA_0 & 0x08) ? 3 : 2;
	return true;
}

/* ASIC thermal sensor RTL837X_TM_RESULT is signed 16-bit in 1/128 deg C. */
bool snmp_hw_temp(__xdata int16_t *__xdata deci_c) __banked
{
	__xdata int16_t raw;
	__xdata uint16_t mag;
	if (!stat_ready() || !access(RTL837X_TM_RESULT, SFR_EXEC_READ_REG))
		return false;
	raw = (int16_t)(((uint16_t)SFR_DATA_8 << 8) | SFR_DATA_0);
	if (raw < 0) {
		mag = (uint16_t)(-(int32_t)raw);
		*deci_c = -(int16_t)(((uint32_t)mag * 10UL) >> 7);
	} else {
		mag = (uint16_t)raw;
		*deci_c = (int16_t)(((uint32_t)mag * 10UL) >> 7);
	}
	return true;
}

bool snmp_hw_sfp_ddm(uint8_t sfp, __xdata uint8_t reg, __xdata uint16_t *__xdata raw) __banked
{
	if (sfp >= machine.n_sfp)
		return false;
#ifdef RTLP_HOST_TEST
	return snmp_hw_sfp_read(sfp, reg, raw);
#else
	if (!stat_ready() || !sfp_read_block(sfp, reg, 2))
		return false;
	*raw = ((uint16_t)sfp_buf[0] << 8) | sfp_buf[1];
	return true;
#endif
}
