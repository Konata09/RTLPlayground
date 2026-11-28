/* Bounded read-only SNMPv2c subset. No allocation, recursion or logging. */
#include "rtl837x_common.h"
#include "rtl837x_sfr.h"
#ifdef RTLP_HOST_TEST
extern bool EA;
#else
#include <8051.h>
#endif
#include "uip/uip.h"
#include "machine.h"
#include "version.h"
#include "sfp.h"
#include "rtl837x_lldp.h"
#include "snmp.h"
#include "snmp_internal.h"
#include "snmp_hw.h"
#pragma codeseg BANK4
#pragma constseg BANK4
extern __code const struct machine machine;
__xdata uint8_t snmp_response[SNMP_MAX_MESSAGE];
volatile __xdata uint32_t snmp_uptime;
__xdata uint8_t snmp_community[32];
__xdata uint8_t snmp_community_length, snmp_network[4], snmp_mask[4];
__xdata uint8_t snmp_agent_enabled;
__xdata struct uip_udp_conn *__xdata snmp_listener;
struct binding {
	uint16_t offset, length, value_offset, value_length;
};
static __xdata struct binding bindings[SNMP_MAX_VARBINDS];
static __xdata uint32_t arcs[SNMP_MAX_ARCS];
static __xdata uint16_t candidate[20];
static __xdata uint8_t arc_count, candidate_len;
static __xdata uint8_t found_sec, found_col, found_idx, found_sub;
static __xdata uint8_t walk_sec, walk_col, walk_idx, walk_sub, walk_nb;
static __xdata volatile uint16_t walk_resume;
static __xdata struct snmp_counter counter;
static __xdata uint16_t speed;
static __xdata const uint8_t *__xdata request;
static __xdata uint16_t cursor, pos;
static __xdata uint8_t overflow, count, pdu, request_id[4], id_length;
/* GETBULK fields saturate to 0..0xffff; ordinals number the MIB's slots, 0 = not started. */
static __xdata uint16_t field, bulk_nonrep, bulk_max, slot_no, rep_slot[SNMP_MAX_VARBINDS];
static __xdata uint8_t excess;
#define INT_SKIP 0
#define INT_ID 1
#define INT_FIELD 2
#define REP_ENDED 0xffff
enum {
	SEC_LLDP_LOC = 0,
	SEC_LLDP_LOC_PORT,
	SEC_LLDP_REM,
	SEC_LLDP_REM_MAN,
	SEC_SYS,
	SEC_IF_NUM,
	SEC_IF_TAB,
	SEC_ETHER,
	SEC_IF_X,
	SEC_ENT_PHYS,
	SEC_ENT_SENS,
	SEC_COUNT
};
/* Column and entity lists are in strict numeric order for lexicographic walk. */
static __code const uint8_t lldp_loc_cols[] = {1, 2, 3, 4, 5, 6};
static __code const uint8_t lldp_loc_port_cols[] = {2, 3, 4};
static __code const uint8_t lldp_rem_cols[] = {4, 5, 6, 7, 8, 9, 11, 12};
static __code const uint8_t lldp_man_cols[] = {3, 4};
static __code const uint8_t syscols[] = {1, 2, 3, 4, 5, 6, 7};
static __code const uint8_t ifcols[] = {1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 14, 16, 17, 20};
static __code const uint8_t xcols[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 17, 18};
static __code const uint8_t ent_phys_cols[] = {2, 4, 5, 6, 7, 8, 9, 11, 12, 13, 16};
static __code const uint8_t ent_sens_cols[] = {1, 2, 3, 4, 5, 6};
static __code const uint8_t ent_all[] = {1, 2, 10, 11, 12, 13, 14, 15, 20, 21, 22, 23, 24, 25};
static __code const uint8_t ent_sens[] = {2, 11, 12, 13, 14, 15, 21, 22, 23, 24, 25};
static __code const uint8_t sens_type[5] = {8, 4, 5, 6, 6};
static __code const uint8_t sens_scale[5] = {9, 9, 7, 7, 7};
static __code const uint8_t sens_prec[5] = {1, 4, 0, 1, 1};
static __code const uint8_t sens_reg[5] = {224, 226, 228, 230, 232};
static __code const char *__code const sens_unit[5] = {"C", "V", "uA", "uW", "uW"};
static __code const char *__code const sfp_sens_desc[5] = {
    " Temperature", " Voltage", " TX Bias", " TX Power", " RX Power"};
static __code const char *__code const sfp_sens_name[5] = {
    " Temp", " Vcc", " TxBias", " TxPower", " RxPower"};

void snmp_init(void) __banked
{
	snmp_hw_init();
	memset(snmp_network, 0, 4);
	memset(snmp_mask, 0, 4);
	{
		__xdata uint8_t enabled = EA;
		EA = 0;
		snmp_uptime = 0;
		EA = enabled;
	}
	snmp_agent_enabled = 0;
	snmp_community_length = 0;
	snmp_listener = 0;
}

/* TLV bounds always refer to the immediate parent, not the whole packet. */
static bool tlv(uint8_t tag, __xdata uint16_t end, volatile __xdata uint16_t *__xdata child_end)
{
	__xdata uint16_t length;
	__xdata uint8_t n;
	if (cursor >= end || request[cursor++] != tag || cursor >= end)
		return false;
	n = request[cursor++];
	length = n;
	if (n & 0x80) {
		n &= 0x7f;
		if (!n || n > 2 || (uint16_t)(end - cursor) < n)
			return false;
		length = 0;
		while (n--)
			length = (length << 8) | request[cursor++];
	}
	if (length > end - cursor)
		return false;
	*child_end = cursor + length;
	return true;
}

static bool integer(uint16_t end, __xdata uint8_t mode)
{
	/* SDCC #15242 otherwise spills these XDATA temporaries into scarce DATA. */
	__xdata volatile uint16_t e, n, o;
	__xdata volatile uint8_t i;
	if (!tlv(ASN_INTEGER, end, &e))
		return false;
	n = e - cursor;
	if (!n || n > 4)
		return false;
	if (n > 1 && ((request[cursor] == 0 && !(request[cursor + 1] & 0x80)) ||
		      (request[cursor] == 255 && (request[cursor + 1] & 0x80))))
		return false;
	if (mode == INT_ID) {
		id_length = n;
		for (i = 0; i < n; ++i)
			request_id[i] = request[cursor + i];
	} else if (mode == INT_FIELD) {
		/* Negative is 0. A minimal positive value needing more than 16 bits saturates. */
		field = 0;
		o = cursor;
		if (!(request[o] & 0x80)) {
			if (n == 3 && !request[o]) {
				++o;
				--n;
			}
			if (n > 2)
				field = 0xffff;
			else
				while (n--)
					field = (field << 8) | request[o++];
		}
	}
	cursor = e;
	return true;
}

static bool oid(uint16_t offset, __xdata uint16_t length)
{
	__xdata uint16_t e = offset + length;
	__xdata uint32_t value = 0;
	__xdata uint8_t b, first = 1, start = 1;
	arc_count = 0;
	if (!length)
		return false;
	while (offset < e) {
		b = request[offset++];
		if (start && b == 0x80)
			return false;
		if (value > 0x01ffffffUL) {
			/* Combined first subidentifier can be UINT32_MAX + 80. */
			if (!first || value != 0x02000000UL || (b & 0x80) || b > 79)
				return false;
			arcs[arc_count++] = 2;
			arcs[arc_count++] = ((value << 7) | b) - 80;
			first = 0;
			value = 0;
			start = 1;
			continue;
		}
		value = (value << 7) | (b & 0x7f);
		start = 0;
		if (!(b & 0x80)) {
			if (first) {
				arcs[arc_count++] = value < 40 ? 0 : value < 80 ? 1 : 2;
				value -= value < 40 ? 0 : value < 80 ? 40 : 80;
				first = 0;
			}
			if (arc_count == SNMP_MAX_ARCS)
				return false;
			arcs[arc_count++] = value;
			value = 0;
			start = 1;
		}
	}
	return start && !first;
}

static bool parse(uint16_t length)
{
	__xdata volatile uint16_t outer, comm, pend, list, bind, name, value, boff, voff;
	__xdata volatile uint8_t mode;
	cursor = 0;
	count = 0;
	excess = 0;
	if (!tlv(ASN_SEQUENCE, length, &outer) || outer != length)
		return false;
	if (!tlv(ASN_INTEGER, outer, &value) || value - cursor != 1 || request[cursor] != SNMP_VERSION_2C)
		return false;
	cursor = value;
	if (!tlv(ASN_OCTET_STRING, outer, &comm) || comm - cursor != snmp_community_length ||
	    memcmp(request + cursor, snmp_community, snmp_community_length))
		return false;
	cursor = comm;
	if (cursor >= outer)
		return false;
	pdu = request[cursor];
	if (pdu != SNMP_PDU_GET && pdu != SNMP_PDU_GETNEXT && pdu != SNMP_PDU_GETBULK)
		return false;
	if (!tlv(pdu, outer, &pend) || pend != outer || !integer(pend, INT_ID))
		return false;
	/* Two INTEGERs: error fields (ignored, RFC3416) or GETBULK non-repeaters/max-repetitions. */
	mode = pdu == SNMP_PDU_GETBULK ? INT_FIELD : INT_SKIP;
	if (!integer(pend, mode))
		return false;
	bulk_nonrep = field;
	if (!integer(pend, mode) || !tlv(ASN_SEQUENCE, pend, &list) || list != pend)
		return false;
	bulk_max = field;
	/* Every binding is validated; only the first SNMP_MAX_VARBINDS are kept, the rest flag tooBig. */
	while (cursor < list) {
		if (!tlv(ASN_SEQUENCE, list, &bind) || !tlv(ASN_OBJECT_ID, bind, &name))
			return false;
		boff = cursor;
		if (!oid(cursor, name - cursor))
			return false;
		cursor = name;
		voff = cursor;
		if (cursor >= bind || !tlv(request[cursor], bind, &value) || value != bind)
			return false;
		{
			__xdata uint8_t tag;
			__xdata uint16_t n;
			tag = request[voff];
			n = value - cursor;
			if (tag == ASN_NULL || tag == SNMP_NO_SUCH_OBJECT ||
			    tag == SNMP_NO_SUCH_INSTANCE || tag == SNMP_END_OF_MIB) {
				if (n)
					return false;
			} else if (tag == ASN_INTEGER || tag == ASN_COUNTER32 ||
				   tag == ASN_GAUGE32 || tag == ASN_TIMETICKS ||
				   tag == ASN_COUNTER64 || tag == ASN_UNSIGNED32) {
				if (!n || n > (tag == ASN_INTEGER     ? 4
					       : tag == ASN_COUNTER64 ? 9
								      : 5))
					return false;
				if (n > 1 &&
				    ((request[cursor] == 0 && !(request[cursor + 1] & 0x80)) ||
				     (request[cursor] == 255 && (request[cursor + 1] & 0x80))))
					return false;
				if (tag != ASN_INTEGER &&
				    ((request[cursor] & 0x80) ||
				     (n == (tag == ASN_COUNTER64 ? 9 : 5) && request[cursor])))
					return false;
			} else if (tag == ASN_OBJECT_ID) {
				if (!oid(cursor, n))
					return false;
			} else if (tag == ASN_IP_ADDRESS) {
				if (n != 4)
					return false;
			} else if (tag != ASN_OCTET_STRING && tag != ASN_OPAQUE)
				return false;
		}
		if (count == SNMP_MAX_VARBINDS)
			excess = 1;
		else {
			bindings[count].offset = boff;
			bindings[count].length = name - boff;
			bindings[count].value_offset = voff;
			bindings[count].value_length = bind - voff;
			++count;
		}
		cursor = bind;
	}
	return cursor == list;
}

static uint8_t chip_port(uint8_t index)
{
	__xdata uint8_t i;
	for (i = MACHINE_MIN_PORT;
	     i <= (MACHINE_MAX_PORT < CPU_LOGICAL_PORT ? MACHINE_MAX_PORT : CPU_LOGICAL_PORT - 1); ++i)
		if (machine.log_to_phys_port[i] == index)
			return i;
	return 255;
}

static uint8_t sfp_present(uint8_t sfp)
{
	if (sfp >= machine.n_sfp)
		return 0;
	if (sfp_pins_last & (uint8_t)(1U << (sfp << 2)))
		return 0;
	return 1;
}

static uint8_t sfp_has_ddm(uint8_t sfp)
{
	if (!sfp_present(sfp))
		return 0;
	if (!(sfp_options[sfp] & 0x40))
		return 0;
	if (sfp_options[sfp] & 0x10)
		return 0;
	return 1;
}

static uint8_t sfp_front_port(uint8_t sfp)
{
	__xdata uint8_t i;
	for (i = MACHINE_MIN_PORT;
	     i <= (MACHINE_MAX_PORT < CPU_LOGICAL_PORT ? MACHINE_MAX_PORT : CPU_LOGICAL_PORT - 1); ++i)
		if (machine.is_sfp[i] == (uint8_t)(sfp + 1))
			return machine.log_to_phys_port[i];
	return (uint8_t)(sfp + 1);
}

static bool ent_exists(uint8_t ent)
{
	if (ent == 1 || ent == 2)
		return true;
	if (ent == 10)
		return sfp_present(0);
	if (ent >= 11 && ent <= 15)
		return sfp_has_ddm(0);
	if (ent == 20)
		return sfp_present(1);
	if (ent >= 21 && ent <= 25)
		return sfp_has_ddm(1);
	return false;
}

static uint8_t lldp_rem_find(uint8_t port_num, __xdata uint8_t rem_idx)
{
	__xdata uint8_t i, port = chip_port(port_num), seen = 0;
	if (port == 255)
		return 255;
	for (i = 0; i < LLDP_NB_MAX; ++i) {
		if (lldp_nb[i].ttl && lldp_nb[i].port == port) {
			if (++seen == rem_idx)
				return i;
		}
	}
	return 255;
}

static uint8_t build_prefix(uint8_t sec, __xdata uint8_t col)
{
	if (sec <= SEC_LLDP_REM_MAN) {
		candidate[0] = 1;
		candidate[1] = 0;
		candidate[2] = 8802;
		candidate[3] = 1;
		candidate[4] = 1;
		candidate[5] = 2;
		candidate[6] = 1;
		if (sec == SEC_LLDP_LOC) {
			candidate[7] = 3;
			candidate[8] = col;
			return 9;
		}
		if (sec == SEC_LLDP_LOC_PORT) {
			candidate[7] = 3;
			candidate[8] = 7;
			candidate[9] = 1;
			candidate[10] = col;
			return 11;
		}
		candidate[7] = 4;
		candidate[8] = sec == SEC_LLDP_REM ? 1 : 2;
		candidate[9] = 1;
		candidate[10] = col;
		return 11;
	}
	candidate[0] = 1;
	candidate[1] = 3;
	candidate[2] = 6;
	candidate[3] = 1;
	candidate[4] = 2;
	candidate[5] = 1;
	if (sec == SEC_SYS) {
		candidate[6] = 1;
		candidate[7] = col;
		return 8;
	}
	if (sec == SEC_IF_NUM) {
		candidate[6] = 2;
		candidate[7] = 1;
		return 8;
	}
	if (sec == SEC_IF_TAB) {
		candidate[6] = 2;
		candidate[7] = 2;
		candidate[8] = 1;
		candidate[9] = col;
		return 10;
	}
	if (sec == SEC_ETHER) {
		candidate[6] = 10;
		candidate[7] = 7;
		candidate[8] = 2;
		candidate[9] = 1;
		candidate[10] = col;
		return 11;
	}
	if (sec == SEC_IF_X) {
		candidate[6] = 31;
		candidate[7] = 1;
		candidate[8] = 1;
		candidate[9] = 1;
		candidate[10] = col;
		return 11;
	}
	if (sec == SEC_ENT_PHYS) {
		candidate[6] = 47;
		candidate[7] = 1;
		candidate[8] = 1;
		candidate[9] = 1;
		candidate[10] = 1;
		candidate[11] = col;
		return 12;
	}
	candidate[6] = 99;
	candidate[7] = 1;
	candidate[8] = 1;
	candidate[9] = 1;
	candidate[10] = col;
	return 11;
}

static void build_oid(void)
{
	__xdata volatile uint8_t n = build_prefix(walk_sec, walk_col);
	__xdata volatile uint8_t j;
	if (walk_sec == SEC_LLDP_LOC || walk_sec == SEC_SYS || walk_sec == SEC_IF_NUM) {
		candidate[n] = 0;
		candidate_len = (uint8_t)(n + 1);
	} else if (walk_sec == SEC_LLDP_REM) {
		candidate[11] = 0;
		candidate[12] = walk_idx;
		candidate[13] = walk_sub;
		candidate_len = 14;
	} else if (walk_sec == SEC_LLDP_REM_MAN) {
		candidate[11] = 0;
		candidate[12] = walk_idx;
		candidate[13] = walk_sub;
		candidate[14] = 1;
		candidate[15] = 4;
		for (j = 0; j < 4; ++j)
			candidate[16 + j] = lldp_nb[walk_nb].mgmt_addr[j];
		candidate_len = 20;
	} else {
		candidate[n] = walk_idx;
		candidate_len = (uint8_t)(n + 1);
	}
}

static int8_t compare(void)
{
	__xdata volatile uint8_t i, n = arc_count < candidate_len ? arc_count : candidate_len;
	__xdata volatile uint32_t a;
	__xdata volatile uint16_t c;
	for (i = 0; i < n; ++i) {
		a = arcs[i];
		c = candidate[i];
		if (a > 0xffffUL)
			return 1;
		if ((uint16_t)a < c)
			return -1;
		if ((uint16_t)a > c)
			return 1;
	}
	return arc_count < candidate_len ? -1 : arc_count > candidate_len ? 1 : 0;
}

/* Supported column prefixes distinguish noSuchInstance from noSuchObject even when empty. */
static bool check_prefix(__xdata uint8_t plen)
{
	__xdata volatile uint8_t i;
	__xdata volatile uint32_t a;
	__xdata volatile uint16_t c;
	if (arc_count < plen)
		return false;
	for (i = 0; i < plen; ++i) {
		a = arcs[i];
		c = candidate[i];
		if (a != (uint32_t)c)
			return false;
	}
	return true;
}

static __code const uint16_t sec_spans[SEC_COUNT] = {
    sizeof(lldp_loc_cols),
    sizeof(lldp_loc_port_cols) * 9U,
    sizeof(lldp_rem_cols) * 9U * LLDP_NB_PER_PORT_MAX,
    sizeof(lldp_man_cols) * 9U * LLDP_NB_PER_PORT_MAX,
    sizeof(syscols),
    1U,
    sizeof(ifcols) * 9U,
    9U,
    sizeof(xcols) * 9U,
    sizeof(ent_phys_cols) * sizeof(ent_all),
    sizeof(ent_sens_cols) * sizeof(ent_sens),
};

static uint8_t sec_col_count(uint8_t sec)
{
	switch (sec) {
	case SEC_LLDP_LOC:
		return sizeof(lldp_loc_cols);
	case SEC_LLDP_LOC_PORT:
		return sizeof(lldp_loc_port_cols);
	case SEC_LLDP_REM:
		return sizeof(lldp_rem_cols);
	case SEC_LLDP_REM_MAN:
		return sizeof(lldp_man_cols);
	case SEC_SYS:
		return sizeof(syscols);
	case SEC_IF_NUM:
		return 1;
	case SEC_IF_TAB:
		return sizeof(ifcols);
	case SEC_ETHER:
		return 1;
	case SEC_IF_X:
		return sizeof(xcols);
	case SEC_ENT_PHYS:
		return sizeof(ent_phys_cols);
	default:
		return sizeof(ent_sens_cols);
	}
}

static uint8_t sec_col_at(uint8_t sec, __xdata uint8_t c)
{
	switch (sec) {
	case SEC_LLDP_LOC:
		return lldp_loc_cols[c];
	case SEC_LLDP_LOC_PORT:
		return lldp_loc_port_cols[c];
	case SEC_LLDP_REM:
		return lldp_rem_cols[c];
	case SEC_LLDP_REM_MAN:
		return lldp_man_cols[c];
	case SEC_SYS:
		return syscols[c];
	case SEC_IF_NUM:
		return 0;
	case SEC_IF_TAB:
		return ifcols[c];
	case SEC_ETHER:
		return 19;
	case SEC_IF_X:
		return xcols[c];
	case SEC_ENT_PHYS:
		return ent_phys_cols[c];
	default:
		return ent_sens_cols[c];
	}
}

static uint8_t sec_idx_count(uint8_t sec)
{
	if (sec == SEC_LLDP_LOC || sec == SEC_SYS || sec == SEC_IF_NUM)
		return 1;
	if (sec == SEC_ENT_PHYS)
		return sizeof(ent_all);
	if (sec == SEC_ENT_SENS)
		return sizeof(ent_sens);
	return 9;
}

static uint8_t sec_is_port(uint8_t sec)
{
	switch (sec) {
	case SEC_LLDP_LOC_PORT:
	case SEC_LLDP_REM:
	case SEC_LLDP_REM_MAN:
	case SEC_IF_TAB:
	case SEC_ETHER:
	case SEC_IF_X:
		return 1;
	default:
		return 0;
	}
}

static uint8_t lookup(__xdata uint16_t resume)
{
	/* SDCC #15242 otherwise spills XDATA temporaries into scarce DATA.
	 * Single main-loop owner: volatile controls placement, not concurrency. */
	__xdata volatile uint8_t sec, c, ncols, col, i, nidx, sub, nsub, idx, nb_slot, prefix = 0;
	__xdata volatile uint16_t s = 0, span;
	walk_resume = resume;
	for (sec = 0; sec < SEC_COUNT; ++sec) {
		span = sec_spans[sec];
		if (walk_resume && (uint16_t)(s + span) < walk_resume) {
			s = (uint16_t)(s + span);
			continue;
		}
		ncols = sec_col_count(sec);
		nidx = sec_idx_count(sec);
		nsub = (sec == SEC_LLDP_REM || sec == SEC_LLDP_REM_MAN) ? LLDP_NB_PER_PORT_MAX : 1;
		for (c = 0; c < ncols; ++c) {
			col = sec_col_at(sec, c);
			if (!walk_resume && pdu == SNMP_PDU_GET) {
				if (check_prefix(build_prefix(sec, col)))
					prefix = 1;
			}
			for (i = 0; i < nidx; ++i) {
				if (sec == SEC_ENT_PHYS)
					idx = ent_all[i];
				else if (sec == SEC_ENT_SENS)
					idx = ent_sens[i];
				else
					idx = (uint8_t)(i + 1);
				if (sec_is_port(sec) && chip_port(idx) == 255) {
					s = (uint16_t)(s + nsub);
					continue;
				}
				if ((sec == SEC_ENT_PHYS || sec == SEC_ENT_SENS) && !ent_exists(idx)) {
					++s;
					continue;
				}
				for (sub = 1; sub <= nsub; ++sub) {
					++s;
					if (s < walk_resume)
						continue;
					nb_slot = 255;
					if (sec == SEC_LLDP_REM || sec == SEC_LLDP_REM_MAN) {
						nb_slot = lldp_rem_find(idx, sub);
						if (nb_slot == 255) {
							s = (uint16_t)(s + (uint8_t)(nsub - sub));
							break;
						}
						if (sec == SEC_LLDP_REM_MAN &&
						    !(lldp_nb[nb_slot].mgmt_addr[0] |
						      lldp_nb[nb_slot].mgmt_addr[1] |
						      lldp_nb[nb_slot].mgmt_addr[2] |
						      lldp_nb[nb_slot].mgmt_addr[3]))
							continue;
					}
					walk_sec = sec;
					walk_col = col;
					walk_idx = idx;
					walk_sub = sub;
					walk_nb = nb_slot;
					build_oid();
					if (walk_resume ? s > walk_resume
					    : pdu != SNMP_PDU_GET ? compare() < 0
								  : compare() == 0) {
						slot_no = s;
						found_sec = sec;
						found_col = col;
						found_idx = idx;
						found_sub = nb_slot;
						if ((sec == SEC_IF_TAB && col == 5) ||
						    (sec == SEC_IF_X && col == 15)) {
							if (!snmp_hw_speed(chip_port(idx), &speed))
								return SNMP_LOOKUP_HW_ERROR;
						}
						return 0;
					}
				}
			}
		}
	}
	return pdu != SNMP_PDU_GET ? SNMP_END_OF_MIB
	       : prefix		       ? SNMP_NO_SUCH_INSTANCE
				       : SNMP_NO_SUCH_OBJECT;
}

/* Reverse writer: payload precedes its header, with checked subtraction. */
static void put(uint8_t b)
{
	if (!pos) {
		overflow = 1;
		return;
	}
	snmp_response[--pos] = b;
}
static void wrap(uint8_t tag, __xdata uint16_t end)
{
	__xdata uint16_t length = end - pos;
	if (length < 128)
		put(length);
	else {
		put(length);
		if (length > 255) {
			put(length >> 8);
			put(0x82);
		} else
			put(0x81);
	}
	put(tag);
}
static void bytes(uint8_t tag, __xdata const uint8_t *__xdata data, __xdata uint16_t length)
{
	__xdata uint16_t end = pos;
	while (length)
		put(data[--length]);
	wrap(tag, end);
}
static void number(uint8_t tag, __xdata uint32_t value)
{
	__xdata uint16_t end = pos;
	__xdata uint8_t last;
	do {
		last = value;
		put(last);
		value >>= 8;
	} while (value);
	if (last & 0x80)
		put(0);
	wrap(tag, end);
}
static void signed_int(__xdata int32_t v)
{
	__xdata uint16_t end = pos;
	__xdata uint32_t u = (uint32_t)v;
	__xdata uint8_t b;
	if (v >= 0) {
		number(ASN_INTEGER, u);
		return;
	}
	for (;;) {
		b = (uint8_t)u;
		put(b);
		u = (u >> 8) | 0xff000000UL;
		if (u == 0xffffffffUL && (b & 0x80))
			break;
	}
	wrap(ASN_INTEGER, end);
}
static void text_x(__xdata const char *s, __xdata uint8_t cap)
{
	__xdata uint8_t n = 0;
	while (n < cap && s[n])
		++n;
	bytes(ASN_OCTET_STRING, (const __xdata uint8_t *)s, n);
}
static void put_code_raw(__code const char *s, __xdata uint8_t cap)
{
	__xdata uint8_t n = 0;
	while (n < cap && s[n])
		++n;
	while (n)
		put((uint8_t)s[--n]);
}
static void text_c(__code const char *s, __xdata uint8_t cap)
{
	__xdata uint16_t end = pos;
	put_code_raw(s, cap);
	wrap(ASN_OCTET_STRING, end);
}
static void put_sysdescr(void)
{
	__xdata uint16_t end = pos;
	put_code_raw(VERSION_SW, sizeof(VERSION_SW));
	put_code_raw(" RTLPlayground ", 16);
	put_code_raw(machine.machine_name, sizeof(machine.machine_name));
	wrap(ASN_OCTET_STRING, end);
}
static void put_port_label(uint8_t index, __xdata uint8_t is_sfp)
{
	__xdata uint16_t end = pos;
	put((uint8_t)('0' + index));
	put(' ');
	put_code_raw(is_sfp ? "SFP" : "Port", 4);
	wrap(ASN_OCTET_STRING, end);
}
static uint8_t rev8(uint8_t b)
{
	__xdata uint8_t r = 0, i;
	for (i = 0; i < 8; ++i) {
		r = (uint8_t)((r << 1) | (b & 1));
		b >>= 1;
	}
	return r;
}
static void lldp_caps_bits(__xdata uint16_t caps)
{
	__xdata uint16_t end = pos;
	__xdata uint8_t hi = rev8((uint8_t)(caps >> 8));
	if (hi)
		put(hi);
	put(rev8((uint8_t)(caps & 0xff)));
	wrap(ASN_OCTET_STRING, end);
}
static void native_counter(uint8_t tag)
{
	__xdata uint8_t start = tag == ASN_COUNTER64 ? 0 : 4, i = 8;
	__xdata uint16_t end = pos;
	while (start < 7 && !counter.bytes[start])
		++start;
	while (i > start)
		put(counter.bytes[--i]);
	if (counter.bytes[start] & 0x80)
		put(0);
	wrap(tag, end);
}
static void put_subid(__xdata uint16_t v)
{
	put((uint8_t)(v & 0x7f));
	v >>= 7;
	while (v) {
		put((uint8_t)((v & 0x7f) | 0x80));
		v >>= 7;
	}
}
static void candidate_oid(void)
{
	__xdata uint8_t i = candidate_len;
	__xdata uint16_t end = pos;
	while (i > 2)
		put_subid(candidate[--i]);
	put_subid((uint16_t)candidate[0] * 40U + candidate[1]);
	wrap(ASN_OBJECT_ID, end);
}
static bool value_lldp(void)
{
	__xdata volatile uint8_t sec = found_sec, col = found_col, index = found_idx, port, nb;
	if (sec == SEC_LLDP_LOC) {
		if (col == 1)
			number(ASN_INTEGER, LLDP_CHASSIS_ID_TLV_SUBTYPE);
		else if (col == 2)
			bytes(ASN_OCTET_STRING, uip_ethaddr.addr, 6);
		else if (col == 3)
			text_x(hostname, sizeof(hostname));
		else if (col == 4)
			put_sysdescr();
		else
			lldp_caps_bits(LLDP_CAPABILITY_BRIDGE);
		return true;
	}
	if (sec == SEC_LLDP_LOC_PORT) {
		port = chip_port(index);
		if (col == 2)
			number(ASN_INTEGER, LLDP_PORT_ID_TLV_SUBTYPE);
		else if (col == 3)
			put_port_label(index, 0);
		else if (port_names[port][0])
			text_x(port_names[port], PORT_NAME_SIZE);
		else
			put_port_label(index, machine.is_sfp[port]);
		return true;
	}
	nb = found_sub;
	if (sec == SEC_LLDP_REM) {
		if (col == 4)
			number(ASN_INTEGER, lldp_nb[nb].chassis_subtype);
		else if (col == 5)
			bytes(ASN_OCTET_STRING, lldp_nb[nb].chassis, lldp_nb[nb].chassis_len);
		else if (col == 6)
			number(ASN_INTEGER,
			       lldp_nb[nb].port_id_mac ? LLDP_PORT_ID_SUBTYPE_MAC
						       : LLDP_PORT_ID_TLV_SUBTYPE);
		else if (col == 7) {
			if (lldp_nb[nb].port_id_mac)
				bytes(ASN_OCTET_STRING,
				      (const __xdata uint8_t *)lldp_nb[nb].port_id, 6);
			else
				text_x(lldp_nb[nb].port_id, LLDP_NB_PORT_ID_LENGTH);
		} else if (col == 8)
			text_x(lldp_nb[nb].port_desc, LLDP_NB_PORT_DESC_LENGTH);
		else if (col == 9)
			text_x(lldp_nb[nb].sys_name, LLDP_NB_SYS_NAME_LENGTH);
		else
			lldp_caps_bits(lldp_nb[nb].caps);
		return true;
	}
	number(ASN_INTEGER, col == 3 ? LLDP_MGMT_IF_NUMBERING_UNKNOWN : 0);
	return true;
}
static bool value_entity(void)
{
	__xdata volatile uint8_t col = found_col, ent = found_idx, sfp, sub, fp;
	__xdata uint16_t end, raw;
	__xdata int16_t temp;
	sfp = ent >= 20 ? 1 : 0;
	if (found_sec == SEC_ENT_PHYS) {
		if (col == 2 || col == 7) {
			if (ent == 1)
				text_c(col == 2 ? machine.machine_name : "Chassis",
				       sizeof(machine.machine_name));
			else if (ent == 2)
				text_c(col == 2 ? "ASIC Temperature" : "ASIC Temp", 20);
			else {
				fp = sfp_front_port(sfp);
				end = pos;
				if (ent != 10 && ent != 20) {
					sub = (uint8_t)(ent - (sfp ? 21 : 11));
					put_code_raw(col == 2 ? sfp_sens_desc[sub]
							      : sfp_sens_name[sub],
						     16);
				}
				put((uint8_t)('0' + fp));
				put_code_raw("SFP ", 4);
				wrap(ASN_OCTET_STRING, end);
			}
			return true;
		}
		if (col == 4) {
			number(ASN_INTEGER, ent == 1 ? 0 : (ent == 2 || ent == 10 || ent == 20) ? 1 : (sfp ? 20 : 10));
			return true;
		}
		if (col == 5) {
			number(ASN_INTEGER, ent == 1 ? 3 : (ent == 10 || ent == 20) ? 9 : 8);
			return true;
		}
		if (col == 6) {
			if (ent == 1)
				signed_int(-1);
			else if (ent == 2)
				number(ASN_INTEGER, 1);
			else if (ent == 10)
				number(ASN_INTEGER, 2);
			else if (ent == 20)
				number(ASN_INTEGER, 3);
			else
				number(ASN_INTEGER, (uint8_t)(ent - (sfp ? 20 : 10)));
			return true;
		}
		if (col == 8) {
			if (ent == 1)
				text_c(MACHINE_PCB_INFO, 64);
			else
				bytes(ASN_OCTET_STRING, snmp_community, 0);
			return true;
		}
		if (col == 9) {
			if (ent == 1)
				text_c(VERSION_SW, sizeof(VERSION_SW));
			else
				bytes(ASN_OCTET_STRING, snmp_community, 0);
			return true;
		}
		if (col == 11) {
			if (ent == 10 || ent == 20)
				text_x(sfp_module_serial[sfp], 16);
			else
				bytes(ASN_OCTET_STRING, snmp_community, 0);
			return true;
		}
		if (col == 12) {
			if (ent == 1)
				text_c("RTLPlayground", 16);
			else if (ent == 10 || ent == 20)
				text_x(sfp_module_vendor[sfp], 16);
			else
				bytes(ASN_OCTET_STRING, snmp_community, 0);
			return true;
		}
		if (col == 13) {
			if (ent == 1)
				text_c(machine.machine_name, sizeof(machine.machine_name));
			else if (ent == 10 || ent == 20)
				text_x(sfp_module_model[sfp], 16);
			else
				bytes(ASN_OCTET_STRING, snmp_community, 0);
			return true;
		}
		number(ASN_INTEGER, (ent == 10 || ent == 20) ? 1 : 2);
		return true;
	}
	sub = ent == 2 ? 0 : (uint8_t)(ent - (sfp ? 21 : 11));
	if (col == 1) {
		number(ASN_INTEGER, sens_type[sub]);
		return true;
	}
	if (col == 2) {
		number(ASN_INTEGER, sens_scale[sub]);
		return true;
	}
	if (col == 3) {
		number(ASN_INTEGER, sens_prec[sub]);
		return true;
	}
	if (col == 6) {
		text_c(sens_unit[sub], 8);
		return true;
	}
	if (col == 5) {
		if (ent == 2)
			number(ASN_INTEGER, 1);
		else
			number(ASN_INTEGER, snmp_hw_sfp_ddm(sfp, sens_reg[sub], &raw) ? 1 : 2);
		return true;
	}
	if (ent == 2) {
		if (!snmp_hw_temp(&temp))
			return false;
		signed_int((int32_t)temp);
		return true;
	}
	if (!snmp_hw_sfp_ddm(sfp, sens_reg[sub], &raw)) {
		signed_int(0);
		return true;
	}
	if (sub == 0) {
		__xdata uint16_t mag;
		temp = (int16_t)raw;
		if (temp < 0) {
			mag = (uint16_t)(-(int32_t)temp);
			signed_int(-(int32_t)(((uint32_t)mag * 10UL) >> 8));
		} else {
			mag = (uint16_t)temp;
			signed_int((int32_t)(((uint32_t)mag * 10UL) >> 8));
		}
	} else if (sub == 2)
		signed_int((int32_t)((uint32_t)raw << 1));
	else
		signed_int((int32_t)raw);
	return true;
}
static bool value(void)
{
	__xdata volatile uint8_t sec = found_sec, col = found_col, index = found_idx, port, selector;
	__xdata uint32_t v;
	__xdata uint16_t mtu;
	__xdata uint8_t state;
	__xdata bool enabled;
	if (sec <= SEC_LLDP_REM_MAN)
		return value_lldp();
	if (sec >= SEC_ENT_PHYS)
		return value_entity();
	if (sec == SEC_SYS) {
		if (col == 1)
			put_sysdescr();
		else if (col == 2) {
			__xdata uint16_t end = pos;
			put_subid(1);
			put_subid(machine.isRTL8373 ? 8373 : 8372);
			put_subid(3);
			put_subid(1);
			put_subid(6);
			put_subid(43);
			wrap(ASN_OBJECT_ID, end);
		} else if (col == 5)
			text_x(hostname, sizeof(hostname));
		else if (col == 4 || col == 6)
			bytes(ASN_OCTET_STRING, snmp_community, 0);
		else if (col == 7)
			number(ASN_INTEGER, 2);
		else {
			enabled = EA;
			EA = 0;
			v = snmp_uptime;
			EA = enabled;
			number(ASN_TIMETICKS, v);
		}
		return true;
	}
	if (sec == SEC_IF_NUM) {
		v = 0;
		for (index = 1; index <= 9; ++index)
			if (chip_port(index) != 255)
				++v;
		number(ASN_INTEGER, v);
		return true;
	}
	port = chip_port(index);
	if (sec == SEC_ETHER) {
		if (!snmp_hw_duplex(port, &state))
			return false;
		number(ASN_INTEGER, state);
		return true;
	}
	if (sec == SEC_IF_X && col == 17) {
		if (!machine.is_sfp[port])
			state = 1;
		else
			state = sfp_present((uint8_t)(machine.is_sfp[port] - 1)) ? 1 : 2;
		number(ASN_INTEGER, state);
		return true;
	}
	if (sec == SEC_IF_X && col == 18) {
		text_x(port_names[port], PORT_NAME_SIZE);
		return true;
	}
	if (sec == SEC_IF_TAB && col == 4) {
		if (!snmp_hw_mtu(port, &mtu))
			return false;
		number(ASN_INTEGER, mtu);
		return true;
	}
	if (sec == SEC_IF_TAB && col == 6) {
		bytes(ASN_OCTET_STRING, uip_ethaddr.addr, 6);
		return true;
	}
	if (sec == SEC_IF_TAB && col == 7) {
		if (!snmp_hw_admin(port, &state))
			return false;
		number(ASN_INTEGER, state);
		return true;
	}
	if (sec == SEC_IF_TAB && (col == 14 || col == 20)) {
		if (!snmp_hw_counter32(port, 48, col == 14, &counter))
			return false;
		native_counter(ASN_COUNTER32);
		return true;
	}
	if (sec == SEC_IF_TAB && col == 1) {
		number(ASN_INTEGER, index);
		return true;
	}
	if ((sec == SEC_IF_TAB && col == 2) || (sec == SEC_IF_X && col == 1)) {
		put_port_label(index, machine.is_sfp[port]);
		return true;
	}
	if (sec == SEC_IF_TAB && col == 3) {
		number(ASN_INTEGER, 6);
		return true;
	}
	if ((sec == SEC_IF_TAB && col == 5) || (sec == SEC_IF_X && col == 15)) {
		if (sec == SEC_IF_X)
			v = speed;
		else {
			switch (speed) {
			case 0:
				v = 0;
				break;
			case 10:
				v = 10000000UL;
				break;
			case 100:
				v = 100000000UL;
				break;
			case 1000:
				v = 1000000000UL;
				break;
			case 2500:
				v = 2500000000UL;
				break;
			default:
				v = 0xffffffffUL;
				break;
			}
		}
		number(ASN_GAUGE32, v);
		return true;
	}
	if (sec == SEC_IF_TAB && col == 8) {
		if (!snmp_hw_link(port, &v))
			return false;
		/* chip_port() maps only MAC ports 0..8; a 16-bit mask is sufficient. */
		number(ASN_INTEGER, (v & ((uint16_t)1 << port)) ? 1 : 2);
		return true;
	}
	if (sec == SEC_IF_X && col >= 2 && col <= 5)
		selector = col < 4 ? col + 1 : col + 2;
	else
		selector = sec == SEC_IF_X ? (col == 6    ? 0
					      : col == 10 ? 1
					      : col < 10  ? col - 5
							  : col - 6)
			   : col == 10	   ? 0
			   : col == 11	   ? 2
			   : col == 16	   ? 1
					   : 5;
	if (!snmp_hw_counter(port, selector, &counter))
		return false;
	native_counter(sec == SEC_IF_X && col >= 6 ? ASN_COUNTER64 : ASN_COUNTER32);
	return true;
}
/* Exact size of the whole response message for a varbind list of `list` bytes (see envelope). */
static uint16_t hdr_len(__xdata uint16_t n)
{
	return n < 128 ? 2 : n < 256 ? 3 : 4;
}
static uint16_t message_size(__xdata uint16_t list)
{
	__xdata uint16_t body;
	/* PDU: list, request-id, error-status and error-index (3 bytes each). */
	body = hdr_len(list) + list + 2 + id_length + 3 + 3;
	/* Message: version, community, PDU. */
	body += 3 + 2 + snmp_community_length + hdr_len(body);
	return hdr_len(body) + body;
}
static void reverse(__xdata uint16_t lo, __xdata uint16_t hi)
{
	__xdata uint8_t t;
	while (lo + 1 < hi) {
		--hi;
		t = snmp_response[lo];
		snmp_response[lo++] = snmp_response[hi];
		snmp_response[hi] = t;
	}
}
/* GETBULK (RFC3416 4.2.3). Varbinds are produced in wire order. The reverse writer stacks each
 * one below the previous, so each block is byte-reversed as it completes and the whole list
 * once more at the end: block order and contents are then correct without a copy. Per-repeater
 * state is one MIB ordinal. Output stops at the first varbind that no longer fits in
 * SNMP_MAX_MESSAGE (a prefix, RFC3416 4.2.3), after max-repetitions rows, or after a row of
 * endOfMibView only: rows are limited by the response size, never by the request fields.
 * Returns the 1-based input binding that failed in hardware, else 0. */
static uint8_t bulk(void)
{
	__xdata uint8_t b = 0, nrep, live = 0, hit;
	__xdata uint16_t row = 0, end, st;
	nrep = bulk_nonrep < count ? bulk_nonrep : count;
	memset(rep_slot, 0, sizeof(rep_slot));
	for (;;) {
		if (b == nrep && !bulk_max)
			break;
		if (b == count) {
			if (!live || ++row >= bulk_max)
				break;
			b = nrep;
			live = 0;
		}
		st = rep_slot[b];
		end = pos;
		if (st == REP_ENDED)
			hit = SNMP_END_OF_MIB;
		else {
			if (!st)
				oid(bindings[b].offset, bindings[b].length);
			hit = lookup(st);
		}
		if (hit == SNMP_LOOKUP_HW_ERROR)
			return b + 1;
		if (hit) {
			put(0);
			put(hit);
			/* A walked-off repeater repeats its last object (still in candidate). */
			if (st && st != REP_ENDED)
				candidate_oid();
			else {
				bytes(ASN_OBJECT_ID, request + bindings[b].offset, bindings[b].length);
				rep_slot[b] = REP_ENDED;
			}
		} else {
			if (!value())
				return b + 1;
			candidate_oid();
			rep_slot[b] = slot_no;
			if (b >= nrep)
				live = 1;
		}
		wrap(ASN_SEQUENCE, end);
		if (overflow || message_size(SNMP_MAX_MESSAGE - pos) > SNMP_MAX_MESSAGE) {
			pos = end;
			overflow = 0;
			break;
		}
		reverse(pos, end);
		++b;
	}
	reverse(pos, SNMP_MAX_MESSAGE);
	return 0;
}
static void envelope(uint16_t list_end, __xdata uint8_t error, __xdata uint8_t error_index)
{
	__xdata uint16_t pend, end;
	wrap(ASN_SEQUENCE, list_end);
	pend = SNMP_MAX_MESSAGE;
	number(ASN_INTEGER, error_index);
	number(ASN_INTEGER, error);
	bytes(ASN_INTEGER, request_id, id_length);
	wrap(SNMP_PDU_RESPONSE, pend);
	bytes(ASN_OCTET_STRING, snmp_community, snmp_community_length);
	number(ASN_INTEGER, 1);
	end = SNMP_MAX_MESSAGE;
	wrap(ASN_SEQUENCE, end);
}
uint16_t snmp_process(__xdata const uint8_t *__xdata input, __xdata uint16_t length,
		      __xdata const uint8_t *__xdata source) __banked
{
	__xdata volatile uint8_t i, exception, error = 0, error_index = 0;
	__xdata volatile uint16_t end;
	if (!snmp_agent_enabled || !snmp_community_length || !input || !source ||
	    length > SNMP_MAX_MESSAGE)
		return 0;
	if (!source[0] || source[0] == 127 || source[0] >= 224)
		return 0;
	for (i = 0; i < 4; ++i)
		if ((source[i] & snmp_mask[i]) != snmp_network[i])
			return 0;
	if (snmp_mask[0] != 255 || snmp_mask[1] != 255 || snmp_mask[2] != 255 ||
	    snmp_mask[3] < 254) {
		__xdata uint8_t host_set, host_clear;
		host_set = host_clear = 0;
		for (i = 0; i < 4; ++i) {
			host_set |= source[i] & (uint8_t)~snmp_mask[i];
			host_clear |= (uint8_t)~source[i] & (uint8_t)~snmp_mask[i];
		}
		if (!host_set || !host_clear)
			return 0;
	}
	request = input;
	if (!parse(length))
		return 0;
	pos = SNMP_MAX_MESSAGE;
	overflow = 0;
	if (excess)
		error = SNMP_ERR_TOO_BIG; /* valid but too many bindings to store: empty list */
	else if (pdu == SNMP_PDU_GETBULK) {
		error_index = bulk();
		if (error_index)
			error = SNMP_ERR_GEN_ERR;
	} else {
		i = count;
		while (i) {
			--i;
			end = pos;
			oid(bindings[i].offset, bindings[i].length);
			exception = lookup(0);
			if (exception == SNMP_LOOKUP_HW_ERROR) {
				error = SNMP_ERR_GEN_ERR;
				error_index = i + 1;
				break;
			}
			if (exception) {
				put(0);
				put(exception);
				bytes(ASN_OBJECT_ID, request + bindings[i].offset, bindings[i].length);
			} else {
				if (!value()) {
					error = SNMP_ERR_GEN_ERR;
					error_index = i + 1;
					break;
				}
				candidate_oid();
			}
			wrap(ASN_SEQUENCE, end);
		}
	}
	if (error == SNMP_ERR_GEN_ERR) {
		/* genErr echoes the entire original list, with correct error-index. */
		pos = SNMP_MAX_MESSAGE;
		overflow = 0;
		i = count;
		while (i) {
			--i;
			end = pos;
			{
				__xdata uint16_t n;
				n = bindings[i].value_length;
				while (n)
					put(request[bindings[i].value_offset + --n]);
			}
			bytes(ASN_OBJECT_ID, request + bindings[i].offset, bindings[i].length);
			wrap(ASN_SEQUENCE, end);
		}
	}
	envelope(SNMP_MAX_MESSAGE, error, error_index);
	if (overflow) {
		pos = SNMP_MAX_MESSAGE;
		overflow = 0;
		envelope(SNMP_MAX_MESSAGE, SNMP_ERR_TOO_BIG, 0); /* tooBig, empty bindings */
	}
	if (overflow)
		return 0;
	length = SNMP_MAX_MESSAGE - pos;
	for (cursor = 0; cursor < length; ++cursor)
		snmp_response[cursor] = snmp_response[pos + cursor];
	return length;
}
void snmp_callback(void) __banked
{
	__xdata struct uip_udpip_hdr *header;
	__xdata uint16_t length;
	if (!snmp_listener || uip_udp_conn != snmp_listener || !uip_newdata())
		return;
	header = (__xdata struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN];
	if (!uip_ipaddr_cmpx(header->destipaddr, uip_hostaddr))
		return;
	if (!header->srcport)
		return;
	length = snmp_process(uip_appdata, uip_datalen(), (const __xdata uint8_t *)header->srcipaddr);
	if (length) {
		memcpy(uip_appdata, snmp_response, length);
		uip_udp_send(length);
	}
}
