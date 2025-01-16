// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include "avr/assembler.h"
#include "avr/disassembler.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	AVROp aop = { 0 };
	op->size = avr_disassembler(buf, len, a->pc, a->big_endian, &aop, &op->buf_asm);
	if (!op->size) {
		op->size = 2;
		rz_strbuf_set(&op->buf_asm, "invalid");
	}
	return op->size;
}

static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	st32 slen = strlen(str);

	ut8 buffer[16];
	ut32 written = avr_assembler(str, slen, buffer, sizeof(buffer), a->pc, a->big_endian);

	if (written < 1) {
		return -1;
	}

	rz_strbuf_setbin(&ao->buf, (const ut8 *)&buffer, written);
	return (int)written;
}

char **avr_cpu_descriptions() {
	static char *cpu_desc[] = {
		"ATmega8", "8-bit AVR microcontroller with 8KB Flash, 1KB SRAM, and 512B EEPROM",
		"ATmega1280", "8-bit AVR microcontroller with 128KB Flash, 8KB SRAM, and 4KB EEPROM, ideal for complex embedded systems",
		"ATmega1281", "8-bit AVR microcontroller with 128KB Flash, 8KB SRAM, and enhanced peripherals for industrial applications",
		"ATmega16", "8-bit AVR microcontroller with 16KB Flash, 1KB SRAM, and 512B EEPROM, suitable for general-purpose applications",
		"ATmega168", "8-bit AVR microcontroller with 16KB Flash, 1KB SRAM, and 512B EEPROM, widely used in Arduino projects",
		"ATmega2560", "High-performance 8-bit AVR microcontroller with 256KB Flash, 8KB SRAM, and 4KB EEPROM, popular in advanced Arduino boards",
		"ATmega2561", "8-bit AVR microcontroller with 256KB Flash, 8KB SRAM, and enhanced peripherals for embedded systems",
		"ATmega328p", "8-bit AVR microcontroller with 32KB Flash, 2KB SRAM, and 1KB EEPROM, widely used in Arduino Uno",
		"ATmega32u4", "8-bit AVR microcontroller with 32KB Flash, 2.5KB SRAM, and USB support, ideal for HID devices",
		"ATmega48", "8-bit AVR microcontroller with 4KB Flash, 512B SRAM, and 256B EEPROM, designed for cost-sensitive applications",
		"ATmega640", "8-bit AVR microcontroller with 64KB Flash, 4KB SRAM, and 2KB EEPROM, suitable for advanced embedded systems",
		"ATmega88", "8-bit AVR microcontroller with 8KB Flash, 1KB SRAM, and 512B EEPROM, used in compact applications",
		"ATxmega128a4u", "High-performance 8-bit AVR microcontroller with 128KB Flash, 8KB SRAM, and USB support for modern applications",
		"ATTiny48", "8-bit AVR microcontroller with 4KB Flash, 512B SRAM, and compact design for low-power devices",
		"ATTiny88", "8-bit AVR microcontroller with 8KB Flash, 512B SRAM, and compact design for efficient embedded solutions",
		0
	};
	return cpu_desc;
}

RzAsmPlugin rz_asm_plugin_avr = {
	.name = "avr",
	.arch = "avr",
	.license = "LGPL3",
	.bits = 8 | 16,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.desc = "AVR Atmel",
	.disassemble = &disassemble,
	.assemble = &assemble,
	.cpus =
		"ATmega8,"
		"ATmega1280,"
		"ATmega1281,"
		"ATmega16,"
		"ATmega168,"
		"ATmega2560,"
		"ATmega2561,"
		"ATmega328p,"
		"ATmega32u4,"
		"ATmega48,"
		"ATmega640,"
		"ATmega88,"
		"ATxmega128a4u,"
		"ATTiny48,"
		"ATTiny88,",
	.get_cpu_desc = avr_cpu_descriptions,
};
