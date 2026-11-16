#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rtl837x_common.h"
#include "rtl837x_regs.h"
#include "machine.h"
#include "uip.h"
#include "rtl837x_lldp.h"
#include "rtl837x_trap.h"
#include "rtl837x_port.h"

uint8_t uip_buf[UIP_CONF_BUFFER_ALLOC_SIZE];
uint16_t uip_len;
struct uip_eth_addr uip_ethaddr = { .addr = {0x02,0x11,0x22,0x33,0x44,0x55} };
uip_ipaddr_t uip_hostaddr;
char port_names[9][PORT_NAME_SIZE];
const struct machine machine = {
			   .log_to_phys_port = {1, 2, 3, 4, 5, 6, 7, 8, 9} };
char hostname[24] = "rtlplayground";
uint8_t outbuf[2500];
uint16_t slen;
volatile uint32_t ticks;
bool lldp_enabled;
uint8_t sfr_data[4];

static uint32_t links_sts;
static int reg_reads, tx_frames, tx_port[16];
static char lldp_logbuf[1024];
static size_t lldp_loglen;

void print_string(const char *s)
{
	while (*s && lldp_loglen + 1 < sizeof(lldp_logbuf))
		lldp_logbuf[lldp_loglen++] = *s++;
	lldp_logbuf[lldp_loglen] = 0;
}
void write_char(char c)
{
	if (lldp_loglen + 1 < sizeof(lldp_logbuf))
		lldp_logbuf[lldp_loglen++] = c;
	lldp_logbuf[lldp_loglen] = 0;
}
void tcpip_output(void)
{
	uint16_t m = HTONS(((struct rtl_tag *)&uip_buf[RTL_FRAME_DESC_SIZE + 2 * MAC_ADDR_LEN])->pmask);
	uint8_t i;

	tx_frames++;
	for (i = 0; i < 16; i++)
		if ((m >> i) & 1)
			tx_port[i]++;
}

void reg_read_m(uint16_t reg_addr)
{
	if (reg_addr == RTL837X_REG_LINKS_STS)
		reg_reads++;
	sfr_data[0] = 0;
	sfr_data[1] = links_sts;
	sfr_data[2] = links_sts >> 8;
	sfr_data[3] = 0;
}

void memcpyc(uint8_t *dst, const uint8_t *src, uint16_t len) { memcpy(dst, src, len); }
uint16_t strlen_x(const char *s) { return strlen(s); }
uint16_t strtox(uint8_t *dst, const char *s) { uint16_t n = strlen(s); memcpy(dst, s, n); return n; }
volatile uint16_t SFR_DATA_U16;
void phy_read(uint8_t phy_id, uint8_t dev_id, uint16_t reg) { (void)phy_id; (void)dev_id; (void)reg; }
uint16_t port_pvid_get(uint8_t port) { (void)port; return 1; }
uint8_t port_lag_of(uint8_t port) { (void)port; return 0xff; }

static int failures;
#define CHECK(cond, name) do { \
	if (cond) printf("PASS  %s\n", name); \
	else { printf("FAIL  %s\n", name); failures++; } \
} while (0)

static void step(int seconds)
{
	while (seconds--) {
		ticks += SYS_TICK_HZ;
		lldp_tick();
	}
}

static void put(uint8_t slot, uint8_t port, uint16_t ttl)
{
	lldp_nb[slot].port = port;
	lldp_nb[slot].ttl = ttl;
}

static const uint8_t ap_mac[] = {0x94, 0x2a, 0x6f, 0xd2, 0x25, 0x6e};

static bool frame(uint8_t port, uint8_t chassis_subtype, const char *chassis, uint8_t chassis_len,
		  uint8_t subtype, const char *id, uint8_t id_len)
{
	uint8_t *p = uip_buf;

	memset(uip_buf, 0, sizeof(uip_buf));
	memcpy(p, LLDP_MULTICAST_ADDR, MAC_ADDR_LEN);
	p = uip_buf + TRAP_RX_HDR_SIZE - 1;
	*p++ = port;
	*p++ = LLDP_ETHERTYPE >> 8;
	*p++ = LLDP_ETHERTYPE & 0xff;
	*p++ = LLDP_CHASSIS_ID_TLV_TYPE << 1;
	*p++ = chassis_len + 1;
	*p++ = chassis_subtype;
	memcpy(p, chassis, chassis_len);
	p += chassis_len;
	*p++ = LLDP_PORT_ID_TLV_TYPE << 1;
	*p++ = id_len + 1;
	*p++ = subtype;
	memcpy(p, id, id_len);
	p += id_len;
	*p++ = LLDP_TTL_TLV_TYPE << 1;
	*p++ = LLDP_TTL_TLV_LENGTH;
	*p++ = 0;
	*p++ = 120;
	*p++ = 0;
	*p++ = 0;
	uip_len = p - uip_buf;
	return lldp_in();
}

static void reset(bool enabled, uint16_t links)
{
	ticks = 0;
	lldp_init();
	lldp_enabled = enabled;
	links_sts = links;
	reg_reads = tx_frames = 0;
	memset(tx_port, 0, sizeof(tx_port));
	lldp_loglen = 0;
	lldp_logbuf[0] = 0;
}

static bool frame_no_chassis(uint8_t port, uint16_t ttl)
{
	uint8_t *p = uip_buf;

	memset(uip_buf, 0, sizeof(uip_buf));
	memcpy(p, LLDP_MULTICAST_ADDR, MAC_ADDR_LEN);
	p = uip_buf + TRAP_RX_HDR_SIZE - 1;
	*p++ = port;
	*p++ = LLDP_ETHERTYPE >> 8;
	*p++ = LLDP_ETHERTYPE & 0xff;
	*p++ = LLDP_PORT_ID_TLV_TYPE << 1;
	*p++ = 5;
	*p++ = LLDP_PORT_ID_TLV_SUBTYPE;
	memcpy(p, "eth0", 4);
	p += 4;
	*p++ = LLDP_TTL_TLV_TYPE << 1;
	*p++ = LLDP_TTL_TLV_LENGTH;
	*p++ = ttl >> 8;
	*p++ = ttl & 0xff;
	*p++ = 0;
	*p++ = 0;
	uip_len = p - uip_buf;
	return lldp_in();
}

int main(void)
{
	uint8_t i;
	int busy = 0;
	int sent;

	reset(true, 0x0108);
	put(0, 3, 120);
	put(1, 8, 120);
	step(5);
	CHECK(lldp_nb[0].ttl == 115 && lldp_nb[1].ttl == 115 && reg_reads == 5,
	      "L1 link up on ports 3 and 8: one second off the TTL per step");

	links_sts = 0x0100;
	step(1);
	CHECK(lldp_nb[0].ttl == 0 && lldp_nb[1].ttl == 114,
	      "L2 port 3 loses its link: its entry is freed, port 8 keeps counting");

	links_sts = 0x0008;
	step(1);
	CHECK(lldp_nb[1].ttl == 0, "L3 port 8 loses its link: the second byte of the mask is read");

	reset(true, 0x0001);
	put(0, 0, 2);
	put(1, 0, 0);
	step(2);
	CHECK(lldp_nb[0].ttl == 0 && lldp_nb[1].ttl == 0, "L4 TTL runs out with the link up, a free slot stays free");

	reset(false, 0x01ff);
	put(0, 3, 120);
	step(LLDP_TX_INTERVAL_S + LLDP_TX_INTERVAL_S / 2);
	CHECK(reg_reads == 0 && tx_frames == 0 && lldp_nb[0].ttl == 120,
	      "L5 LLDP off: no link read, no ageing, nothing sent");

	lldp_enabled = true;
	step(1);
	sent = tx_frames;
	CHECK(sent == MACHINE_MAX_PORT - MACHINE_MIN_PORT + 1 && tx_port[MACHINE_MIN_PORT] == 1 && tx_port[MACHINE_MAX_PORT] == 1, "L6 after lldp on, one frame at once on every port with a link");
	step(LLDP_TX_INTERVAL_S - 1);
	CHECK(tx_frames == sent, "L7 then nothing until the interval");
	step(1);
	CHECK(tx_frames == 2 * sent, "L7b one frame per port after the interval");

	for (i = 0; i < LLDP_NB_MAX; i++)
		put(i, 3, 120);
	lldp_init();
	for (i = 0; i < LLDP_NB_MAX; i++)
		busy += lldp_nb[i].ttl != 0;
	CHECK(busy == 0, "L8 lldp off frees every slot of the table");

	reset(true, 0x01ff);
	frame(7, LLDP_CHASSIS_ID_TLV_SUBTYPE, (const char *)ap_mac, MAC_ADDR_LEN, LLDP_PORT_ID_SUBTYPE_MAC, (const char *)ap_mac, MAC_ADDR_LEN);
	slen = 0;
	lldp_neighbors_to_html();
	outbuf[slen] = 0;
	CHECK(lldp_nb[0].port == 7 && strstr((char *)outbuf, "\"portId\":\"94:2a:6f:d2:25:6e\""),
	      "L9 a MAC address port ID is shown as aa:bb:cc:dd:ee:ff");
	CHECK(frame(8, LLDP_CHASSIS_ID_TLV_SUBTYPE, (const char *)ap_mac, MAC_ADDR_LEN, LLDP_PORT_ID_TLV_SUBTYPE, "GigabitEthernet1/0/24", 21)
	      && !strcmp(lldp_nb[1].port_id, "GigabitEther") && !lldp_nb[1].port_id_mac,
	      "L10 an interface name port ID is cut at 12 characters");
	CHECK(frame(6, LLDP_CHASSIS_ID_TLV_SUBTYPE, (const char *)ap_mac, MAC_ADDR_LEN, LLDP_PORT_ID_TLV_SUBTYPE, "\x94*o\xd2%n", MAC_ADDR_LEN)
	      && !strcmp(lldp_nb[2].port_id, ".*o.%n"),
	      "L11 six bytes with another subtype stay text with dots for the unprintable");
	CHECK(frame(5, LLDP_PORT_ID_TLV_SUBTYPE, "94:2a:6f:d2:25:6e", 17, LLDP_PORT_ID_TLV_SUBTYPE, "eth0", 4)
	      && lldp_nb[3].chassis_len == 17 && !memcmp(lldp_nb[3].chassis, "94:2a:6f:d2:25:6e", 17),
	      "L12 a MAC address sent as text is kept whole as the chassis ID");

	reset(true, 0x0108);
	step(6);
	memset(tx_port, 0, sizeof(tx_port));
	frame(3, LLDP_CHASSIS_ID_TLV_SUBTYPE, (const char *)ap_mac, MAC_ADDR_LEN, LLDP_PORT_ID_TLV_SUBTYPE, "eth0", 4);
	step(LLDP_FAST_TX_COUNT);
	CHECK(tx_port[3] == LLDP_FAST_TX_COUNT && tx_port[8] == 0,
	      "L12 a new neighbour gets the fast frames one second apart on its port alone");
	step(LLDP_TX_INTERVAL_S - 1);
	sent = tx_port[3];
	step(1);
	CHECK(sent == LLDP_FAST_TX_COUNT && tx_port[3] == sent + 1,
	      "L12b after the fast frames the port is back to the interval");
	frame(3, LLDP_CHASSIS_ID_TLV_SUBTYPE, (const char *)ap_mac, MAC_ADDR_LEN, LLDP_PORT_ID_TLV_SUBTYPE, "eth0", 4);
	step(LLDP_FAST_TX_COUNT);
	CHECK(tx_port[3] == sent + 1, "L13 a neighbour heard again is not new");

	links_sts = 0x0128;
	step(LLDP_FAST_TX_COUNT);
	CHECK(tx_port[5] == 1, "L14 a port whose link comes up gets one frame at once, not the fast frames");

	sent = tx_port[8];
	lldp_logical_port_status = 0xfeff;
	frame(8, LLDP_CHASSIS_ID_TLV_SUBTYPE, (const char *)ap_mac, MAC_ADDR_LEN, LLDP_PORT_ID_TLV_SUBTYPE, "eth1", 4);
	step(LLDP_FAST_TX_COUNT);
	CHECK(lldp_nb[1].port == 8 && tx_port[8] == sent, "L15 nothing is sent on a blocked port, a new neighbour there included");
	lldp_logical_port_status = 0xffff;

	reset(true, 0x0108);
	for (i = 0; i < LLDP_NB_MAX; i++)
		put(i, 8, 100);
	frame(3, LLDP_CHASSIS_ID_TLV_SUBTYPE, (const char *)ap_mac, MAC_ADDR_LEN, LLDP_PORT_ID_TLV_SUBTYPE, "eth0", 4);
	step(LLDP_FAST_TX_COUNT);
	CHECK(lldp_nb[0].port == 3 && tx_port[3] == 1,
	      "L16 a neighbour that pushes the oldest out of a full table gets no fast frames");
	CHECK(strstr(lldp_logbuf, "LLDP: neighbour evicted on port 9:") && strstr(lldp_logbuf, "LLDP: neighbour found on port 4:  (eth0)"),
	      "L17 full table eviction logs both evicted and found events");

	reset(true, 0x0010);
	frame(4, LLDP_CHASSIS_ID_TLV_SUBTYPE, (const char *)ap_mac, MAC_ADDR_LEN, LLDP_PORT_ID_SUBTYPE_MAC, (const char *)ap_mac, MAC_ADDR_LEN);
	CHECK(strstr(lldp_logbuf, "LLDP: neighbour found on port 5:  (94:2a:6f:d2:25:6e)"),
	      "L18 neighbour found log formats MAC port IDs safely");
	step(7);
	slen = 0;
	lldp_neighbors_to_html();
	outbuf[slen] = 0;
	CHECK(lldp_uptime_s - lldp_nb[0].seen == 7 && strstr((char *)outbuf, "\"age\":7"),
	      "L19 last-seen age counts elapsed seconds in /lldp.json");
	frame(4, LLDP_CHASSIS_ID_TLV_SUBTYPE, (const char *)ap_mac, MAC_ADDR_LEN, LLDP_PORT_ID_SUBTYPE_MAC, (const char *)ap_mac, MAC_ADDR_LEN);
	CHECK(lldp_uptime_s - lldp_nb[0].seen == 0, "L20 frame refresh resets last-seen age to 0");

	frame_no_chassis(4, 120);
	lldp_nb[0].ttl = 1;
	lldp_loglen = 0; lldp_logbuf[0] = 0;
	step(1);
	CHECK(lldp_cnt[4].rx == 3 && lldp_cnt[4].discarded == 1 && lldp_cnt[4].ageouts == 1 && lldp_cnt[4].tx > 0
	      && strstr(lldp_logbuf, "LLDP: neighbour expired on port 5:"),
	      "L21 counters track tx/rx/discarded/ageouts and expiry is logged");
	slen = 0;
	lldp_counters_to_html();
	outbuf[slen] = 0;
	CHECK(strstr((char *)outbuf, "\"counters\":[") && strstr((char *)outbuf, "\"discarded\":1,\"ageouts\":1"),
	      "L22 lldp_counters_to_html emits counters JSON");

	lldp_loglen = 0; lldp_logbuf[0] = 0;
	frame(4, LLDP_CHASSIS_ID_TLV_SUBTYPE, (const char *)ap_mac, MAC_ADDR_LEN, LLDP_PORT_ID_SUBTYPE_MAC, (const char *)ap_mac, MAC_ADDR_LEN);
	lldp_loglen = 0; lldp_logbuf[0] = 0;
	/* Trigger shutdown TTL=0 */
	memset(uip_buf, 0, sizeof(uip_buf));
	{
		uint8_t *p = uip_buf + TRAP_RX_HDR_SIZE - 1;
		memcpy(uip_buf, LLDP_MULTICAST_ADDR, MAC_ADDR_LEN);
		*p++ = 4; *p++ = LLDP_ETHERTYPE >> 8; *p++ = LLDP_ETHERTYPE & 0xff;
		*p++ = LLDP_CHASSIS_ID_TLV_TYPE << 1; *p++ = 7; *p++ = LLDP_CHASSIS_ID_TLV_SUBTYPE;
		memcpy(p, ap_mac, 6); p += 6;
		*p++ = LLDP_PORT_ID_TLV_TYPE << 1; *p++ = 7; *p++ = LLDP_PORT_ID_SUBTYPE_MAC;
		memcpy(p, ap_mac, 6); p += 6;
		*p++ = LLDP_TTL_TLV_TYPE << 1; *p++ = 2; *p++ = 0; *p++ = 0;
		*p++ = 0; *p++ = 0;
		uip_len = p - uip_buf;
	}
	lldp_in();
	CHECK(lldp_nb[0].ttl == 0 && strstr(lldp_logbuf, "LLDP: neighbour gone on port 5:"),
	      "L23 TTL=0 frame clears neighbour and logs gone");
	lldp_init();
	CHECK(lldp_cnt[4].rx == 0 && lldp_cnt[4].tx == 0 && lldp_cnt[4].discarded == 0 && lldp_cnt[4].ageouts == 0,
	      "L24 lldp_init clears port counters");

	printf("\n%s (%d failure%s)\n", failures ? "SANDBOX: FAILURES" : "SANDBOX: ALL PASS",
	       failures, failures == 1 ? "" : "s");
	return failures ? 1 : 0;
}
