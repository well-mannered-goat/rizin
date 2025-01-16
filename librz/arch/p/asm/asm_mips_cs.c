// SPDX-FileCopyrightText: 2024 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2013-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <mips/mips_internal.h>
#include <capstone/capstone.h>
#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(mips_asm);

static int mips_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;

	cs_insn *insn;
	cs_mode mode = 0;
	int n, ret = -1;
	if (!op) {
		return 0;
	}

	if (!cs_mode_from_cpu(a->cpu, a->bits, a->big_endian, &mode)) {
		rz_asm_op_set_asm(op, "invalid");
		return -1;
	}

	memset(op, 0, sizeof(RzAsmOp));
	op->size = 4;
	if (ctx->omode != mode) {
		cs_close(&ctx->handle);
		ctx->handle = 0;
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(CS_ARCH_MIPS, mode, &ctx->handle);
		if (ret) {
			RZ_LOG_ERROR("failed to open capstone\n");
			goto fin;
		}
		ctx->omode = mode;
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
#if CS_NEXT_VERSION > 5
		cs_option(ctx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NO_DOLLAR);
#endif
	}
	if (a->syntax == RZ_ASM_SYNTAX_REGNUM) {
		cs_option(ctx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else {
		cs_option(ctx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	}
	n = cs_disasm(ctx->handle, (ut8 *)buf, len, a->pc, 1, &insn);
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
#if CS_NEXT_VERSION < 6
		op->size = mode & CS_MODE_MICRO ? 2 : 4;
#else
		op->size = mode & (CS_MODE_MICRO | CS_MODE_NANOMIPS | CS_MODE_MIPS16) ? 2 : 4;
#endif
		goto fin;
	}
	if (insn->size < 1) {
		goto fin;
	}
	op->size = insn->size;
	rz_asm_op_setf_asm(op, "%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);

#if CS_NEXT_VERSION < 6
	// CS_OPT_SYNTAX_NO_DOLLAR is not available before capstone 6
	char *str = rz_asm_op_get_asm(op);
	if (str) {
		// remove the '$'<registername> in the string
		rz_str_replace_char(str, '$', 0);
	}
#endif
	cs_free(insn, n);
fin:
	return op->size;
}

static int mips_assemble(RzAsm *a, RzAsmOp *op, const char *str) {
	ut8 *opbuf = (ut8 *)rz_strbuf_get(&op->buf);
	int ret = mips_assemble_opcode(str, a->pc, opbuf);
	if (a->big_endian) {
		ut8 *buf = opbuf;
		ut8 tmp = buf[0];
		buf[0] = buf[3];
		buf[3] = tmp;
		tmp = buf[1];
		buf[1] = buf[2];
		buf[2] = tmp;
	}
	return ret;
}

char **mips_cpu_descriptions() {
	static char *cpu_desc[] = {
		"mips3", "MIPS III: 64-bit architecture introduced in R4000, supporting advanced memory management.",
		"mips1", "MIPS I: First-generation 32-bit architecture, simple and efficient RISC design.",
		"mips2", "MIPS II: Enhanced 32-bit architecture with additional instructions for improved performance.",
		"mips32r2", "MIPS32 Release 2: 32-bit architecture with improved DSP support and enhanced instructions.",
		"mips32r3", "MIPS32 Release 3: 32-bit architecture focusing on embedded systems and efficiency.",
		"mips32r5", "MIPS32 Release 5: Advanced 32-bit architecture with enhanced virtualization and security features.",
		"mips32r6", "MIPS32 Release 6: Latest 32-bit architecture, optimized for performance and power efficiency.",
		"mips4", "MIPS IV: 64-bit architecture introduced in R8000, targeting high-performance computing.",
		"mips5", "MIPS V: 64-bit architecture with advanced multimedia instructions for digital signal processing.",
		"mips64r2", "MIPS64 Release 2: 64-bit architecture with support for high-performance and embedded applications.",
		"mips64r3", "MIPS64 Release 3: Advanced 64-bit architecture optimized for embedded systems.",
		"mips64r5", "MIPS64 Release 5: High-performance 64-bit architecture with enhanced security features.",
		"mips64r6", "MIPS64 Release 6: Latest 64-bit architecture, offering improved power efficiency and performance.",
		"octeon", "OCTEON: Specialized MIPS architecture for Cavium's multi-core processors, targeting networking.",
		"octeonp", "OCTEON+ : Enhanced version of OCTEON architecture with additional cores and improved performance.",
		"nanomips", "NanoMIPS: Compact instruction set designed for embedded systems and power-sensitive applications.",
		"nms1", "NanoMIPS Release 1: Initial release of the NanoMIPS architecture for low-power devices.",
		"i7200", "i7200: MIPS architecture optimized for high-performance embedded applications.",
		"micromips", "microMIPS: Compact version of MIPS architecture for reduced code size and power consumption.",
		"micro32r3", "microMIPS32 Release 3: Compact 32-bit architecture optimized for embedded systems.",
		"micro32r6", "microMIPS32 Release 6: Latest compact 32-bit architecture with enhanced performance.",
		"r2300", "R2300: Early MIPS processor for workstations, based on the MIPS I architecture.",
		"r2600", "R2600: MIPS processor with improved performance, based on MIPS II architecture.",
		"r2800", "R2800: High-performance MIPS processor with support for advanced applications.",
		"r2000a", "R2000A: Enhanced version of the R2000, MIPS I processor with minor improvements.",
		"r2000", "R2000: First commercial MIPS processor, based on the MIPS I architecture.",
		"r3000a", "R3000A: Enhanced version of the R3000, supporting higher clock speeds and improved memory management.",
		"r3000", "R3000: Second-generation MIPS processor, introducing improved performance and efficiency.",
		"r10000", "R10000: High-performance MIPS processor with out-of-order execution and advanced caching.",
		"noptr64", "NoPtr64: MIPS configuration without support for 64-bit pointers, targeting specific use cases.",
		"nofloat", "NoFloat: MIPS configuration without floating-point unit, designed for cost-sensitive applications.",
		0
	};

	return cpu_desc;
}

RzAsmPlugin rz_asm_plugin_mips_cs = {
	.name = "mips",
	.desc = "Capstone MIPS disassembler",
	.license = "BSD",
	.arch = "mips",
	.cpus = MIPS_CPUS,
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = mips_asm_init,
	.fini = mips_asm_fini,
	.disassemble = &mips_disassemble,
	.mnemonics = mips_asm_mnemonics,
	.assemble = &mips_assemble,
	.get_cpu_desc = mips_cpu_descriptions,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_mips_cs,
	.version = RZ_VERSION
};
#endif
