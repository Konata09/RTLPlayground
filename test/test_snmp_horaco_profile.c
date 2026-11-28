/* Actual machine/SWTGW218AS.c profile; hardware edge stays mocked. */
#define SNMP_HORACO_CONTROL_CLOCK
#define SNMP_REAL_MACHINE
#define SNMP_TRANSPORT_TEST
#define SNMP_TEST_NINE
#include "test_snmp.c"
#include "rtl837x_pins.h"
void udp_callbacks(void)
{
	snmp_callback();
}
int main(void)
{
	assert(machine.isRTL8373 && MACHINE_MIN_PORT == 0 && MACHINE_MAX_PORT == 8);
	assert(machine.mac_flash_offset == 0x1fc000 && machine.n_sfp == 1);
	assert(machine.sfp_port[0].pin_detect == GPIO30_ACL_BIT3_EN);
	assert(machine.sfp_port[0].pin_los == GPIO37 && machine.reset_pin == GPIO54_ACL_BIT2_EN);
	uip_init();
	uip_ipaddr(uip_hostaddr, 192, 0, 2, 1);
	snmp_init();
	assert(test_snmp_configure(comm, sizeof(comm) - 1, network, acl));
	query_oid(2, 0, 0);
	make_request(0xa0, 1);
	decode_response(snmp_process(req, req_len, source));
	CHECK(result_type[0] == 2 && result_len[0] == 1 && result_data[0][0] == 9,
	      "real HORACO ifNumber is nine, excluding CPU");
	for (uint8_t index = 1; index <= 9; index++) {
		assert(machine.log_to_phys_port[index - 1] == index &&
		       machine.phys_to_log_port[index - 1] == index - 1);
		query_oid(31, 6, index);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == 0x46 && last_port == index - 1 && last_selector == 0,
		      "real HORACO HC row maps to physical MAC");
	}
	query_oid(2, 2, 9);
	make_request(0xa0, 1);
	decode_response(snmp_process(req, req_len, source));
	CHECK(result_type[0] == 4 && result_len[0] == 5 && !memcmp(result_data[0], "SFP 9", 5),
	      "real HORACO SFP is front-panel row nine");
	query_oid(2, 1, 10);
	make_request(0xa0, 1);
	decode_response(snmp_process(req, req_len, source));
	CHECK(result_type[0] == 0x81, "real HORACO CPU MAC9 has no synthesized row ten");
	query_oid(1, 1, 0);
	make_request(0xa0, 1);
	decode_response(snmp_process(req, req_len, source));
	CHECK(result_type[0] == 4 &&
		  !memcmp(result_data[0], machine.machine_name, strlen(machine.machine_name)),
	      "sysDescr uses actual HORACO machine name");
	query_oid(2, 2, 9);
	make_request(0xa1, 1);
	decode_response(snmp_process(req, req_len, source));
	CHECK(result_type[0] == 2 && names[0][8] == 3 && names[0][9] == 1,
	      "real HORACO GETNEXT crosses column in numeric order");
	/* RTL8373 sysObjectID + SFP+ ENTITY-MIB / ENTITY-SENSOR-MIB DDM tests. */
	query_oid(1, 2, 0);
	make_request(0xa0, 1);
	decode_response(snmp_process(req, req_len, source));
	{
		const uint8_t exp8373[] = {43, 6, 1, 3, 0xc1, 0x35, 1};
		CHECK(result_type[0] == ASN_OBJECT_ID && result_len[0] == sizeof(exp8373) &&
			  !memcmp(result_data[0], exp8373, sizeof(exp8373)),
		      "HORACO RTL8373 sysObjectID returns 1.3.6.1.3.8373.1");
	}
	sfp_pins_last = 0x33; /* SFP absent */
	query_oid(31, 17, 9);
	make_request(0xa0, 1);
	decode_response(snmp_process(req, req_len, source));
	CHECK(result_type[0] == ASN_INTEGER && result_data[0][0] == 2,
	      "HORACO SFP absent -> ifConnectorPresent=false(2)");
	{
		const uint16_t sfp_ent[] = {1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 2, 10};
		query_arcs(sfp_ent, 13);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == SNMP_NO_SUCH_INSTANCE, "absent SFP has no entity 10");
	}
	/* Plug in DAC module (no DDM): entity 10 exists, 11..15 absent. */
	sfp_pins_last = 0x30;
	sfp_options[0] = 0x00;
	strcpy(sfp_module_vendor[0], "Amphenol");
	strcpy(sfp_module_model[0], "NDAQGG-F306");
	strcpy(sfp_module_serial[0], "APF1649306915K");
	query_oid(31, 17, 9);
	make_request(0xa0, 1);
	decode_response(snmp_process(req, req_len, source));
	CHECK(result_type[0] == ASN_INTEGER && result_data[0][0] == 1,
	      "HORACO SFP present -> ifConnectorPresent=true(1)");
	{
		const uint16_t sfp_desc[] = {1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 2, 10};
		const uint16_t sfp_cls[] = {1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 5, 10};
		const uint16_t sfp_ser[] = {1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 11, 10};
		const uint16_t sfp_mfg[] = {1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 12, 10};
		const uint16_t sfp_mod[] = {1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 13, 10};
		const uint16_t sfp_fru[] = {1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 16, 10};
		const uint16_t sfp_ddm_t[] = {1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 4, 11};
		query_arcs(sfp_desc, 13);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == ASN_OCTET_STRING && result_len[0] == 5 &&
			  !memcmp(result_data[0], "SFP 9", 5),
		      "SFP module entity 10 descr=SFP 9");
		query_arcs(sfp_cls, 13);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == ASN_INTEGER && result_data[0][0] == 9, "SFP entity class=module(9)");
		query_arcs(sfp_ser, 13);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == ASN_OCTET_STRING && result_len[0] == 14 &&
			  !memcmp(result_data[0], "APF1649306915K", 14),
		      "SFP entity serial");
		query_arcs(sfp_mfg, 13);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == ASN_OCTET_STRING && result_len[0] == 8 &&
			  !memcmp(result_data[0], "Amphenol", 8),
		      "SFP entity vendor");
		query_arcs(sfp_mod, 13);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == ASN_OCTET_STRING && result_len[0] == 11 &&
			  !memcmp(result_data[0], "NDAQGG-F306", 11),
		      "SFP entity model");
		query_arcs(sfp_fru, 13);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == ASN_INTEGER && result_data[0][0] == 1, "SFP entity isFRU=true(1)");
		query_arcs(sfp_ddm_t, 12);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == SNMP_NO_SUCH_INSTANCE, "non-DDM SFP hides sensors 11..15");

		/* External calibration (bit 4 set) also hides direct DDM sensors. */
		sfp_options[0] = 0x50;
		execute();
		CHECK(result_type[0] == SNMP_NO_SUCH_INSTANCE, "externally calibrated SFP hides DDM");

		/* Internally calibrated DDM (bit 6 set, bit 4 clear): expose all 5 sensors. */
		sfp_options[0] = 0x40;
		measured_sfp_ddm[0][224] = 0x2a80; /* +42.5 C -> 425 */
		measured_sfp_ddm[0][226] = 33120;  /* 3.3120 V */
		measured_sfp_ddm[0][228] = 6200;   /* 12400 uA */
		measured_sfp_ddm[0][230] = 5000;   /* 500.0 uW */
		measured_sfp_ddm[0][232] = 3200;   /* 320.0 uW */
		execute();
		CHECK(!response_error && result_type[0] == ASN_INTEGER && result_len[0] == 2 &&
			  result_data[0][0] == (425 >> 8) && result_data[0][1] == (425 & 0xff),
		      "SFP DDM temp +42.5 C -> 425");
		measured_sfp_ddm[0][224] = (uint16_t)-2688; /* -10.5 C -> -105 (0x97) */
		execute();
		CHECK(!response_error && result_type[0] == ASN_INTEGER && result_len[0] == 1 &&
			  result_data[0][0] == 0x97,
		      "SFP DDM temp -10.5 C -> -105");
		const uint16_t sfp_vcc[] = {1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 4, 12};
		query_arcs(sfp_vcc, 12);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == ASN_INTEGER && result_len[0] == 3 &&
			  result_data[0][0] == 0 && result_data[0][1] == (33120 >> 8) &&
			  result_data[0][2] == (33120 & 0xff),
		      "SFP DDM Vcc 33120 (3.3120 V)");
		const uint16_t sfp_bias[] = {1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 4, 13};
		query_arcs(sfp_bias, 12);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == ASN_INTEGER && result_len[0] == 2 &&
			  result_data[0][0] == (12400 >> 8) && result_data[0][1] == (12400 & 0xff),
		      "SFP DDM TxBias 12400 uA");
		const uint16_t sfp_rx[] = {1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 4, 15};
		query_arcs(sfp_rx, 12);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(result_type[0] == ASN_INTEGER && result_len[0] == 2 &&
			  result_data[0][0] == (3200 >> 8) && result_data[0][1] == (3200 & 0xff),
		      "SFP DDM RxPower 320.0 uW");
		/* I2C read failure returns 0 + operStatus unavailable(2) instead of genErr. */
		sfp_ddm_failed = true;
		execute();
		CHECK(!response_error && result_type[0] == ASN_INTEGER && result_len[0] == 1 &&
			  result_data[0][0] == 0,
		      "SFP DDM I2C failure returns 0 without genErr");
		const uint16_t sfp_rx_st[] = {1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 5, 15};
		query_arcs(sfp_rx_st, 12);
		make_request(0xa0, 1);
		decode_response(snmp_process(req, req_len, source));
		CHECK(!response_error && result_type[0] == ASN_INTEGER && result_data[0][0] == 2,
		      "SFP DDM I2C failure reports operStatus=unavailable(2)");
		sfp_ddm_failed = false;
		execute();
		CHECK(!response_error && result_type[0] == ASN_INTEGER && result_data[0][0] == 1,
		      "SFP DDM recovery reports operStatus=ok(1)");

		/* Full 1.0 walk with SFP+ DDM active verifies strict monotonicity. */
		input_oid[0] = 40;
		input_oid_len = 1;
		uint32_t prev[32], curr[32];
		unsigned prev_n = 0, walked = 0;
		bool monotonic = true;
		for (; walked < REF_MAX; walked++) {
			make_request(SNMP_PDU_GETNEXT, 1);
			execute();
			assert(!response_error);
			if (result_type[0] == SNMP_END_OF_MIB)
				break;
			unsigned curr_n = decode_oid_arcs(names[0], name_len[0], curr, 32);
			if (prev_n && cmp_arcs(prev, prev_n, curr, curr_n) >= 0)
				monotonic = false;
			memcpy(prev, curr, curr_n * sizeof(uint32_t));
			prev_n = curr_n;
			memcpy(input_oid, names[0], name_len[0]);
			input_oid_len = name_len[0];
		}
		/* 6 lldpLoc + 27 lldpLocPort + 36 mib-2 base + 31*9 if + 11*6 sfp ent + 6*5 sfp sens = 444. */
		CHECK(monotonic && walked == 444u && result_type[0] == SNMP_END_OF_MIB,
		      "HORACO full walk with SFP DDM is strictly monotonic (444 OIDs)");
	}
	return failures ? 1 : 0;
}
