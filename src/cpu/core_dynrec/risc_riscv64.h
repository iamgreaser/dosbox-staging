/*
 *  Copyright (C) 2002-2021  The DOSBox Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/* RV64GC (little endian) backend by GreaseMonkey */

// some configuring defines that specify the capabilities of this architecture
// or aspects of the recompiling

// try to use non-flags generating functions if possible
#define DRC_FLAGS_INVALIDATION
// try to replace _simple functions by code
#define DRC_FLAGS_INVALIDATION_DCODE

// calling convention modifier
#define DRC_CALL_CONV	/* nothing */
#define DRC_FC			/* nothing */

// type with the same size as a pointer
#define DRC_PTR_SIZE_IM Bit64u

// special modifier to ignore alignment in loads/stores
#define RV_IGNORE_ALIGNMENT

// if we need inlining, put something in here to make inlining work
#define RV_MAYBE_INLINE
// #define RV_MAYBE_INLINE INLINE

// register mapping
typedef Bit8u HostReg;

#define HOST_zero  0
#define HOST_ra    1
#define HOST_sp    2
#define HOST_gp    3
#define HOST_tp    4
#define HOST_t0    5
#define HOST_t1    6
#define HOST_t2    7
#define HOST_s0    8
#define HOST_s1    9
#define HOST_a0   10
#define HOST_a1   11
#define HOST_a2   12
#define HOST_a3   13
#define HOST_a4   14
#define HOST_a5   15
#define HOST_a6   16
#define HOST_a7   17
#define HOST_s2   18
#define HOST_s3   19
#define HOST_s4   20
#define HOST_s5   21
#define HOST_s6   22
#define HOST_s7   23
#define HOST_s8   24
#define HOST_s9   25
#define HOST_s10  26
#define HOST_s11  27
#define HOST_t3   28
#define HOST_t4   29
#define HOST_t5   30
#define HOST_t6   31

// protect FC_ADDR over function calls if necessaray
// #define DRC_PROTECT_ADDR_REG

// register that holds function return values
#define FC_RETOP HOST_a0

// register used for address calculations, if the ABI does not
// state that this register is preserved across function calls
// then define DRC_PROTECT_ADDR_REG above
#define FC_ADDR HOST_s0

// register that holds the first parameter
#define FC_OP1 HOST_a0

// register that holds the second parameter
#define FC_OP2 HOST_a1

// special register that holds the third parameter for _R3 calls (byte accessible)
#define FC_OP3 HOST_a2

// register that holds byte-accessible temporary values
#define FC_TMP_BA1 HOST_t0

// register that holds byte-accessible temporary values
#define FC_TMP_BA2 HOST_t1

// temporary register for LEA
#define TEMP_REG_DRC HOST_t2

// instruction encodings

#define MAKEOP_R(OPCODE, F3, F7, RD, RS1, RS2) (((OPCODE)&0x7F)|(((RD)&0x1F)<<7)|(((F3)&0x7)<<12)|(((RS1)&0x1F)<<15)|(((RS2)&0x1F)<<20)|(((F7)&0x7F)<<25))
#define MAKEOP_I(OPCODE, F3, RD, RS1, IMM12) (((OPCODE)&0x7F)|(((RD)&0x1F)<<7)|(((F3)&0x7)<<12)|(((RS1)&0x1F)<<15)|(((IMM12)&0xFFF)<<20))
#define MAKEOP_S(OPCODE, F3, RS2, RS1, IMM12) (((OPCODE)&0x7F)|(((F3)&0x7)<<12)|(((RS1)&0x1F)<<15)|(((RS2)&0x1F)<<20)|(((IMM12)&0xFE0)<<20)|(((IMM12)&0x1F)<<7))
#define MAKEOP_U(OPCODE, RD, IMM20U) (((OPCODE)&0x7F)|(((RD)&0x1F)<<7)|(((IMM20U)&0xFFFFF)<<12))

#define MAKEOP_B(OPCODE, F3, RS1, RS2, IMM12) MAKEOP_S(OPCODE, F3, RS2, RS1, (((IMM12)&0x7FE)|(((IMM12)>>1)&0x800)|((((IMM12)>>11)&0x01))))

#define OP_LUI_U(RD, IMM20U) MAKEOP_U(0x37, RD, IMM20U)
#define OP_AUIPC_U(RD, IMM20U) MAKEOP_U(0x17, RD, IMM20U)
#define OP_JALR_I(RD, RS1, IMM12) MAKEOP_I(0x67, 0x0, RD, RS1, IMM12)
#define OP_BEQ_B(RS1, RS2, IMM12) MAKEOP_B(0x63, 0x0, RS1, RS2, IMM12)
#define OP_BNE_B(RS1, RS2, IMM12) MAKEOP_B(0x63, 0x1, RS1, RS2, IMM12)
#define OP_BLT_B(RS1, RS2, IMM12) MAKEOP_B(0x63, 0x4, RS1, RS2, IMM12)
#define OP_BGE_B(RS1, RS2, IMM12) MAKEOP_B(0x63, 0x5, RS1, RS2, IMM12)
#define OP_BLTU_B(RS1, RS2, IMM12) MAKEOP_B(0x63, 0x6, RS1, RS2, IMM12)
#define OP_BGEU_B(RS1, RS2, IMM12) MAKEOP_B(0x63, 0x7, RS1, RS2, IMM12)
#define OP_LB_MEM_I(RD, IMM12, RS1) MAKEOP_I(0x03, 0x0, RD, RS1, IMM12)
#define OP_LH_MEM_I(RD, IMM12, RS1) MAKEOP_I(0x03, 0x1, RD, RS1, IMM12)
#define OP_LW_MEM_I(RD, IMM12, RS1) MAKEOP_I(0x03, 0x2, RD, RS1, IMM12)
#define OP_LD_MEM_I(RD, IMM12, RS1) MAKEOP_I(0x03, 0x3, RD, RS1, IMM12)
#define OP_LBU_MEM_I(RD, IMM12, RS1) MAKEOP_I(0x03, 0x4, RD, RS1, IMM12)
#define OP_LHU_MEM_I(RD, IMM12, RS1) MAKEOP_I(0x03, 0x5, RD, RS1, IMM12)
#define OP_LWU_MEM_I(RD, IMM12, RS1) MAKEOP_I(0x03, 0x6, RD, RS1, IMM12)
#define OP_SB_MEM_S(RS2, IMM12, RS1) MAKEOP_S(0x23, 0x0, RS2, RS1, IMM12)
#define OP_SH_MEM_S(RS2, IMM12, RS1) MAKEOP_S(0x23, 0x1, RS2, RS1, IMM12)
#define OP_SW_MEM_S(RS2, IMM12, RS1) MAKEOP_S(0x23, 0x2, RS2, RS1, IMM12)
#define OP_SD_MEM_S(RS2, IMM12, RS1) MAKEOP_S(0x23, 0x3, RS2, RS1, IMM12)
#define OP_ADDID_I(RD, RS1, IMM12) MAKEOP_I(0x13, 0x0, RD, RS1, IMM12)
#define OP_ADDIW_I(RD, RS1, IMM12) MAKEOP_I(0x1B, 0x0, RD, RS1, IMM12)
#define OP_SLLID_I(RD, RS1, SHAMT) MAKEOP_I(0x13, 0x1, RD, RS1, ((SHAMT)&0x3F))
#define OP_XORI_I(RD, RS1, IMM12) MAKEOP_I(0x13, 0x4, RD, RS1, IMM12)
#define OP_ORI_I(RD, RS1, IMM12) MAKEOP_I(0x13, 0x6, RD, RS1, IMM12)
#define OP_ANDI_I(RD, RS1, IMM12) MAKEOP_I(0x13, 0x7, RD, RS1, IMM12)
#define OP_SRLID_I(RD, RS1, SHAMT) MAKEOP_I(0x13, 0x5, RD, RS1, ((SHAMT)&0x3F))
#define OP_SRAID_I(RD, RS1, SHAMT) MAKEOP_I(0x13, 0x5, RD, RS1, ((SHAMT)&0x3F)|0x400)
#define OP_SLLIW_I(RD, RS1, SHAMT) MAKEOP_I(0x33, 0x1, RD, RS1, ((SHAMT)&0x1F))
#define OP_SRLIW_I(RD, RS1, SHAMT) MAKEOP_I(0x33, 0x5, RD, RS1, ((SHAMT)&0x1F))
#define OP_SRAIW_I(RD, RS1, SHAMT) MAKEOP_I(0x33, 0x5, RD, RS1, ((SHAMT)&0x1F)|0x400)
#define OP_ADDD_R(RD, RS1, RS2) MAKEOP_R(0x33, 0x0, 0x00, RD, RS1, RS2)
#define OP_ADDW_R(RD, RS1, RS2) MAKEOP_R(0x3B, 0x0, 0x00, RD, RS1, RS2)
#define OP_XOR_R(RD, RS1, RS2) MAKEOP_R(0x33, 0x4, 0x00, RD, RS1, RS2)
#define OP_OR_R(RD, RS1, RS2) MAKEOP_R(0x33, 0x6, 0x00, RD, RS1, RS2)
#define OP_AND_R(RD, RS1, RS2) MAKEOP_R(0x33, 0x7, 0x00, RD, RS1, RS2)

// Pseudo-ops
#define OP_NOP() OP_ADDID_I(HOST_zero, HOST_zero, 0);

static Bit32u temps_in_use = 0;

#define RV_CONST_POOL_ENTRY_MAX 256
struct rv_const_pool_entry {
	Bit32u *auipc_loc;
	Bit64s const_value;
} rv_const_pool[RV_CONST_POOL_ENTRY_MAX];
static Bit32u rv_const_pool_idx = 0;

static void gen_abort_helper(const char *msg) {
	fprintf(stderr, "%s\n", msg);
	__asm__("ebreak\n");
	abort();
	for (;;) {}
}

static HostReg lock_temp(void) {
	if (!(temps_in_use & 0x1)) {
		temps_in_use |= 0x1;
		return HOST_t3;
	}
	if (!(temps_in_use & 0x2)) {
		temps_in_use |= 0x2;
		return HOST_t4;
	}
	if (!(temps_in_use & 0x4)) {
		temps_in_use |= 0x4;
		return HOST_t5;
	}
	if (!(temps_in_use & 0x8)) {
		temps_in_use |= 0x8;
		return HOST_t6;
	}
	gen_abort_helper("no more temp regs");
	for (;;) {}
}
static void unlock_temp(HostReg reg) {
	Bit32u bit_mask;

	switch (reg) {
		case HOST_t3:
			bit_mask = (1<<0U);
			break;
		case HOST_t4:
			bit_mask = (1<<1U);
			break;
		case HOST_t5:
			bit_mask = (1<<2U);
			break;
		case HOST_t6:
			bit_mask = (1<<3U);
			break;
		default:
			gen_abort_helper("invalid temp");
			return;
	}
	if (temps_in_use & bit_mask) {
		temps_in_use &= ~bit_mask;
	} else {
		gen_abort_helper("temp double-freed");
	}
}

// generate a constant pool
static void gen_constant_pool_helper(void) {
	// first do an alignment
	if ((Bit64u)cache.pos & 1) { cache_addb(0); }
	if ((Bit64u)cache.pos & 2) { cache_addw(0); }
	if ((Bit64u)cache.pos & 4) { cache_addd(0); }

	// then swim through the constant pool
	for (Bit32u idx = 0; idx < rv_const_pool_idx; idx++) {
		Bit64s const_loc = (Bit64s)(cache.pos);
		cache_addq(rv_const_pool[idx].const_value);
		Bit32u *auipc_loc = rv_const_pool[idx].auipc_loc;
		Bit64s pc = (Bit64s)auipc_loc;
		Bit64s delta = (const_loc - pc);
		if (!(delta >= -0x80000000L && delta <= 0x7FFFFFFFL)) {
			gen_abort_helper("out-of-range constant\n");
		}
		auipc_loc[0] |= OP_AUIPC_U(HOST_zero, ((delta+0x800)>>12));
		auipc_loc[1] |= OP_LD_MEM_I(HOST_zero, (delta&0xFFF), HOST_zero);
	}

	// finally flush the pool
	rv_const_pool_idx = 0;
}

// move a full register from reg_src to reg_dst
static void gen_mov_regs(HostReg reg_dst,HostReg reg_src) {
	if(reg_src == reg_dst) return;
	cache_addd(OP_ADDID_I(reg_dst, reg_src, 0));
}

// move a 32bit constant value into dest_reg
static void gen_mov_dword_to_reg_imm(HostReg dest_reg,Bit32u imm) {
	if((Bit32u)(imm+0x800) < 0x1000) {
		cache_addd(OP_ADDID_I(dest_reg, HOST_zero, imm));
	} else {
		cache_addd(OP_LUI_U(dest_reg, (imm+0x800)>>12));
		cache_addd(OP_ADDIW_I(dest_reg, HOST_zero, imm&0xFFF));
	}
}


static void gen_addr_direct(HostReg dest_reg, HostReg base_reg, Bit64s addr) {
	// TODO: Faster, more concise versions of this --GM
	if (addr >= -0x800L && addr <= 0x7FFL) {
		// 12 bits
		cache_addd(OP_ADDID_I(dest_reg, base_reg, 0xFFF&(addr)));
	} else if (addr >= -0x80000000L && addr <= 0x7FFFFFFFL) {
		// 32 bits
		cache_addd(OP_LUI_U(dest_reg, 0xFFFFF&((addr+0x800)>>12)));
		cache_addd(OP_ADDIW_I(dest_reg, dest_reg, 0xFFF&(addr)));
		if (base_reg != HOST_zero) {
			cache_addd(OP_ADDD_R(dest_reg, dest_reg, base_reg));
		}
	} else if (rv_const_pool_idx < RV_CONST_POOL_ENTRY_MAX) {
		// Add a value to the constant pool
		rv_const_pool[rv_const_pool_idx].auipc_loc = (Bit32u *)(cache.pos);
		rv_const_pool[rv_const_pool_idx].const_value = addr;
		rv_const_pool_idx += 1;
		cache_addd(OP_AUIPC_U(dest_reg, 0));
		cache_addd(OP_LD_MEM_I(dest_reg, 0, dest_reg));
		if (base_reg != HOST_zero) {
			cache_addd(OP_ADDD_R(dest_reg, dest_reg, base_reg));
		}
	} else {
		// More than 32 bits
		// FIXME: This is terrible --GM
		cache_addd(OP_LUI_U(dest_reg, 0xFFFFF&(((addr>>32L)+0x800)>>12)));
		cache_addd(OP_ADDIW_I(dest_reg, dest_reg, 0xFFF&((addr>>32L))));
		cache_addd(OP_SLLID_I(dest_reg, dest_reg, 11));
		cache_addd(OP_ADDID_I(dest_reg, dest_reg, 0x7FF&(addr>>21L)));
		cache_addd(OP_SLLID_I(dest_reg, dest_reg, 11));
		cache_addd(OP_ADDID_I(dest_reg, dest_reg, 0x7FF&(addr>>10L)));
		cache_addd(OP_SLLID_I(dest_reg, dest_reg, 10));
		cache_addd(OP_ADDID_I(dest_reg, dest_reg, 0x3FF&(addr)));
		if (base_reg != HOST_zero) {
			cache_addd(OP_ADDD_R(dest_reg, dest_reg, base_reg));
		}
	}
}

static void gen_addr_into(HostReg dest_reg, Bit64s addr) {
	gen_addr_direct(dest_reg, HOST_zero, addr);
}

// load a potentially-unaligned 8bit value from memory
// offs is from -0x800 to +0x7FF
static void gen_load_byte_helper(HostReg dest_reg, HostReg mem_reg, Bit64s offs, Bit32s align) {
	if (!(offs >= -0x800L && offs <= 0x7FFL)) {
		gen_abort_helper("offs out of range");
		return;
	}

	// 8bit values cannot be unaligned.
	cache_addd(OP_LBU_MEM_I(dest_reg, offs, mem_reg));
}

// load a potentially-unaligned 16bit value from memory
// offs is from -0x800 to +0x7FE
static void gen_load_word_helper(HostReg dest_reg, HostReg mem_reg, Bit64s offs, Bit32s align) {
	if (!(offs >= -0x800L && offs <= 0x7FEL)) {
		gen_abort_helper("offs out of range");
		return;
	}

	// TODO: unaligned handlers --GM
	cache_addd(OP_LHU_MEM_I(dest_reg, offs, mem_reg));
}

// load a potentially-unaligned 32bit value from memory
// offs is from -0x800 to +0x7FC
static void gen_load_dword_helper(HostReg dest_reg, HostReg mem_reg, Bit64s offs, Bit32s align) {
	if (!(offs >= -0x800L && offs <= 0x7FCL)) {
		gen_abort_helper("offs out of range");
		return;
	}

	// TODO: unaligned handlers --GM
	cache_addd(OP_LW_MEM_I(dest_reg, offs, mem_reg));
}

// load a potentially-unaligned 64bit value from memory
// offs is from -0x800 to +0x7F8
static void gen_load_qword_helper(HostReg dest_reg, HostReg mem_reg, Bit64s offs, Bit32s align) {
	if (!(offs >= -0x800L && offs <= 0x7F8L)) {
		gen_abort_helper("offs out of range");
		return;
	}

	// TODO: unaligned handlers --GM
	cache_addd(OP_LD_MEM_I(dest_reg, offs, mem_reg));
}

// store a potentially-unaligned 8bit value to memory
// offs is from -0x800 to +0x7FF
static void gen_store_byte_helper(HostReg src_reg, HostReg mem_reg, Bit64s offs, Bit32s align) {
	if (!(offs >= -0x800L && offs <= 0x7FFL)) {
		gen_abort_helper("offs out of range");
		return;
	}

	// 8bit values cannot be unaligned.
	cache_addd(OP_SB_MEM_S(src_reg, offs, mem_reg));
}

// store a potentially-unaligned 16bit value to memory
// offs is from -0x800 to +0x7FE
static void gen_store_word_helper(HostReg src_reg, HostReg mem_reg, Bit64s offs, Bit32s align) {
	if (!(offs >= -0x800L && offs <= 0x7FEL)) {
		gen_abort_helper("offs out of range");
		return;
	}

	// TODO: unaligned handlers --GM
	cache_addd(OP_SH_MEM_S(src_reg, offs, mem_reg));
}

// store a potentially-unaligned 32bit value to memory
// offs is from -0x800 to +0x7FC
static void gen_store_dword_helper(HostReg src_reg, HostReg mem_reg, Bit64s offs, Bit32s align) {
	if (!(offs >= -0x800L && offs <= 0x7FCL)) {
		gen_abort_helper("offs out of range");
		return;
	}

	// TODO: unaligned handlers --GM
	cache_addd(OP_SW_MEM_S(src_reg, offs, mem_reg));
}

// store a potentially-unaligned 64bit value to memory
// offs is from -0x800 to +0x7F8
static void gen_store_qword_helper(HostReg src_reg, HostReg mem_reg, Bit64s offs, Bit32s align) {
	if (!(offs >= -0x800L && offs <= 0x7F8L)) {
		gen_abort_helper("offs out of range");
		return;
	}

	// TODO: unaligned handlers --GM
	cache_addd(OP_SD_MEM_S(src_reg, offs, mem_reg));
}


// move a 32bit (dword==true) or 16bit (dword==false) value from memory into dest_reg
// 16bit moves may destroy the upper 16bit of the destination register
static void gen_mov_word_to_reg(HostReg dest_reg,void* data,bool dword) {
	HostReg temp1 = lock_temp();
	gen_addr_into(temp1, (Bit64s)data);
	if (dword) {
		gen_load_dword_helper(dest_reg, temp1, 0, ((Bit64s)data) & 3);
	} else {
		gen_load_word_helper(dest_reg, temp1, 0, ((Bit64s)data) & 1);
	}
	unlock_temp(temp1);
}

static void gen_mov_qword_to_reg(HostReg dest_reg,void* data) {
	HostReg temp1 = lock_temp();
	gen_addr_into(temp1, (Bit64s)data);
	gen_load_qword_helper(dest_reg, temp1, 0, ((Bit64s)data) & 7);
	unlock_temp(temp1);
}

// move an 8bit value from memory into dest_reg
// the upper 24bit of the destination register can be destroyed
// this function does not use FC_OP1/FC_OP2 as dest_reg as these
// registers might not be directly byte-accessible on some architectures
static void gen_mov_byte_to_reg_low(HostReg dest_reg, void *data) {
	HostReg temp1 = lock_temp();
	gen_addr_into(temp1, (Bit64s)data);
	gen_load_byte_helper(dest_reg, temp1, 0, 0);
	unlock_temp(temp1);
}

// move 32bit (dword==true) or 16bit (dword==false) of a register into memory
static void gen_mov_word_from_reg(HostReg src_reg,void* dest,bool dword) {
	HostReg temp1 = lock_temp();
	gen_addr_into(temp1, (Bit64s)dest);
	if (dword) {
		gen_store_dword_helper(src_reg, temp1, 0, ((Bit64s)dest) & 3);
	} else {
		gen_store_word_helper(src_reg, temp1, 0, ((Bit64s)dest) & 1);
	}
	unlock_temp(temp1);
}

// move the lowest 8bit of a register into memory
static void gen_mov_byte_from_reg_low(HostReg src_reg, void *dest) {
	HostReg temp1 = lock_temp();
	gen_addr_into(temp1, (Bit64s)dest);
	gen_store_byte_helper(src_reg, temp1, 0, 0);
	unlock_temp(temp1);
}

static void gen_mov_qword_from_reg(HostReg src_reg,void* dest) {
	HostReg temp1 = lock_temp();
	gen_addr_into(temp1, (Bit64s)dest);
	gen_store_qword_helper(src_reg, temp1, 0, ((Bit64s)dest) & 7);
	unlock_temp(temp1);
}

// add a 32bit constant value to a full register
static void gen_add_imm(HostReg reg,Bit32u imm) {
	if (!imm) return;
	if (((Bit32u)(imm+0x800)) <= 0x1000) {
		cache_addd(OP_ADDIW_I(reg, reg, imm));
	} else {
		HostReg temp1 = lock_temp();
		cache_addd(OP_LUI_U(temp1, ((imm+0x800)>>12)));
		if ((imm&0xFFF) != 0) {
			cache_addd(OP_ADDIW_I(temp1, temp1, (imm&0xFFF)));
		}
		cache_addd(OP_ADDW_R(reg, reg, temp1));
		unlock_temp(temp1);
	}
}

static void gen_add64_imm32(HostReg reg,Bit32u imm) {
	if (!imm) return;
	if (((Bit32u)(imm+0x800)) <= 0x1000) {
		cache_addd(OP_ADDID_I(reg, reg, imm));
	} else {
		HostReg temp1 = lock_temp();
		cache_addd(OP_LUI_U(temp1, ((imm+0x800)>>12)));
		if ((imm&0xFFF) != 0) {
			cache_addd(OP_ADDIW_I(temp1, temp1, (imm&0xFFF)));
		}
		cache_addd(OP_ADDD_R(reg, reg, temp1));
		unlock_temp(temp1);
	}
}

// and a 32bit constant value with a full register
static void gen_and_imm(HostReg reg,Bit32u imm) {
	if (!imm) return;
	if (((Bit32u)(imm+0x800)) <= 0x1000) {
		cache_addd(OP_ANDI_I(reg, reg, imm));
	} else {
		HostReg temp1 = lock_temp();
		cache_addd(OP_LUI_U(temp1, ((imm+0x800)>>12)));
		if ((imm&0xFFF) != 0) {
			cache_addd(OP_ADDIW_I(temp1, temp1, (imm&0xFFF)));
		}
		cache_addd(OP_AND_R(reg, reg, temp1));
		unlock_temp(temp1);
	}
}

// move a 32bit constant value into memory
static void gen_mov_direct_dword(void* dest,Bit32u imm) {
	HostReg temp1 = lock_temp();
	gen_mov_dword_to_reg_imm(temp1, imm);
	gen_mov_word_from_reg(temp1, dest, 1);
	unlock_temp(temp1);
}

// move an address into memory
static void RV_MAYBE_INLINE gen_mov_direct_ptr(void *dest, DRC_PTR_SIZE_IM imm) {
	HostReg temp1 = lock_temp();
	gen_addr_into(temp1, (Bit64s)imm);
	gen_mov_qword_from_reg(temp1, dest);
	unlock_temp(temp1);
}

// add a 32bit (dword==true) or 16bit (dword==false) constant value to a memory value
static void RV_MAYBE_INLINE gen_add_direct_word(void* dest,Bit32u imm,bool dword) {
	if(!imm) return;
	HostReg temp1 = lock_temp();
	gen_mov_word_to_reg(temp1, dest, dword);
	gen_add_imm(temp1, imm);
	gen_mov_word_from_reg(temp1, dest, dword);
	unlock_temp(temp1);
}

// subtract a 32bit (dword==true) or 16bit (dword==false) constant value from a memory value
static void RV_MAYBE_INLINE gen_sub_direct_word(void* dest,Bit32u imm,bool dword) {
	gen_add_direct_word(dest, -(Bit32s)imm, dword);
}

// convert an 8bit word to a 32bit dword
// the register is zero-extended (sign==false) or sign-extended (sign==true)
static void gen_extend_byte(bool sign,HostReg reg) {
	if (sign) {
		cache_addd( OP_SLLIW_I(reg, reg, 24) );
		cache_addd( OP_SRAIW_I(reg, reg, 24) );
	} else {
		cache_addd( OP_ANDI_I(reg, reg, 0x0FF) );
	}
}

// convert a 16bit word to a 32bit dword
// the register is zero-extended (sign==false) or sign-extended (sign==true)
static void gen_extend_word(bool sign,HostReg reg) {
	if (sign) {
		cache_addd( OP_SLLIW_I(reg, reg, 16) );
		cache_addd( OP_SRAIW_I(reg, reg, 16) );
	} else {
		cache_addd( OP_SLLIW_I(reg, reg, 16) );
		cache_addd( OP_SRLIW_I(reg, reg, 16) );
	}
}



// generate a call to a parameterless function
static void RV_MAYBE_INLINE gen_call_function_raw(void * func) {
	HostReg temp1 = lock_temp();
	if (((Bit64u)(cache.pos)) & 4) {
		cache_addd(OP_AUIPC_U(HOST_ra, 0));
		// 0
		cache_addd(OP_LD_MEM_I(temp1, 20, HOST_ra));
		cache_addd(OP_ADDID_I(HOST_ra, HOST_ra, 28));
		// 0
		cache_addd(OP_JALR_I(HOST_zero, temp1, 0));
		cache_addd(0);
		// 0
		cache_addq((Bit64s)func);
	} else {
		if (((Bit64u)(cache.pos)) & 7) {
			gen_abort_helper("compressed instructions not supported yet");
		}
		// 0
		cache_addd(OP_AUIPC_U(HOST_ra, 0));
		cache_addd(OP_LD_MEM_I(temp1, 16, HOST_ra));
		// 0
		cache_addd(OP_ADDID_I(HOST_ra, HOST_ra, 28));
		cache_addd(OP_JALR_I(HOST_zero, temp1, 0));
		// 0
		cache_addq((Bit64s)func);
		// 0
		cache_addd(0);
	}
	unlock_temp(temp1);
}

// generate a call to a function with paramcount parameters
// note: the parameters are loaded in the architecture specific way
// using the gen_load_param_ functions below
static RV_MAYBE_INLINE const Bit8u* gen_call_function_setup(void * func,Bitu paramcount,bool fastcall=false) {
	const Bit8u* proc_addr = cache.pos;
	gen_call_function_raw(func);
	return proc_addr;
}

// load an immediate value as param'th function parameter
static void RV_MAYBE_INLINE gen_load_param_imm(Bitu imm,Bitu param) {
	if (param >= 8) {
		gen_abort_helper("out-of-range param imm");
	}
	gen_mov_dword_to_reg_imm(param+HOST_a0, imm);
}

// load an address as param'th function parameter
static void RV_MAYBE_INLINE gen_load_param_addr(Bitu addr,Bitu param) {
	if (param >= 8) {
		gen_abort_helper("out-of-range param addr");
	}
	gen_mov_dword_to_reg_imm(param+HOST_a0, addr);
}

// load a host-register as param'th function parameter
static void RV_MAYBE_INLINE gen_load_param_reg(Bitu reg,Bitu param) {
	if (param >= 8) {
		gen_abort_helper("out-of-range param reg");
	}
	gen_mov_regs(param+HOST_a0, reg);
}

// load a value from memory as param'th function parameter
static void RV_MAYBE_INLINE gen_load_param_mem(Bitu mem,Bitu param) {
	if (param >= 8) {
		gen_abort_helper("out-of-range param mem");
	}
	gen_mov_word_to_reg(param+HOST_a0, (void *)mem, 1);
}

static void gen_run_code(void) {
	printf("cache pos gen_run_code %p\n", (void *)cache.pos);

	cache_addd(OP_ADDID_I(HOST_sp, HOST_sp, (-(8*2))));
	cache_addd(OP_SD_MEM_S(HOST_ra, (8*0), HOST_sp));
	cache_addd(OP_SD_MEM_S(HOST_s0, (8*1), HOST_sp));
	cache_addd(OP_JALR_I(HOST_zero, HOST_a0, 0));
}

// return from a function
static void gen_return_function(void) {
	//printf("cache pos gen_return_function %p\n", (void *)cache.pos);

	cache_addd(OP_LD_MEM_I(HOST_ra, (8*0), HOST_sp));
	cache_addd(OP_LD_MEM_I(HOST_s0, (8*1), HOST_sp));
	cache_addd(OP_ADDID_I(HOST_sp, HOST_sp, (8*2)));
	cache_addd(OP_JALR_I(HOST_zero, HOST_ra, 0));

	gen_constant_pool_helper();
}

static void gen_jmp_ptr(void * ptr,Bits imm=0) {
	HostReg temp1 = lock_temp();
	gen_mov_qword_to_reg(temp1, ptr);
	gen_add64_imm32(temp1, imm);

	gen_load_qword_helper(temp1, temp1, 0, -1);
	cache_addd(OP_JALR_I(HOST_zero, temp1, 0));
	unlock_temp(temp1);

	gen_constant_pool_helper();
}


// short conditional jump (+-127 bytes) if register is zero
// the destination is set by gen_fill_branch() later
static Bit8u* gen_create_branch_on_zero(HostReg reg, bool dword) {
	HostReg temp1 = lock_temp();
	if (dword) {
		cache_addd( OP_ADDIW_I(temp1, reg, 0) );
	} else {
		cache_addd( OP_SLLID_I(temp1, reg, 48) );
	}
	cache_addd( OP_BNE_B(HOST_zero, temp1, 0) ); // opposite, gets inverted on short branches
	cache_addd( OP_AUIPC_U(temp1, 0) );
	cache_addd( OP_JALR_I(HOST_zero, temp1, 0) );
	unlock_temp(temp1);
	return (Bit8u *)(cache.pos-12);
}

// short conditional jump (+-127 bytes) if register is nonzero
// the destination is set by gen_fill_branch() later
static Bit8u* gen_create_branch_on_nonzero(HostReg reg, bool dword) {
	HostReg temp1 = lock_temp();
	if (dword) {
		cache_addd( OP_ADDIW_I(temp1, reg, 0) );
	} else {
		cache_addd( OP_SLLID_I(temp1, reg, 48) );
	}
	cache_addd( OP_BEQ_B(HOST_zero, temp1, 0) ); // opposite, gets inverted on short branches
	cache_addd( OP_AUIPC_U(temp1, 0) );
	cache_addd( OP_JALR_I(HOST_zero, temp1, 0) );
	unlock_temp(temp1);
	return (Bit8u *)(cache.pos-12);
}

// conditional jump if register is nonzero
// for isdword==true the 32bit of the register are tested
// for isdword==false the lowest 8bit of the register are tested
static Bit8u* gen_create_branch_long_nonzero(HostReg reg, bool dword) {
	HostReg temp1 = lock_temp();
	if (dword) {
		cache_addd( OP_ADDIW_I(temp1, reg, 0) );
	} else {
		cache_addd( OP_ANDI_I(temp1, reg, 0x0FF) );
	}
	cache_addd( OP_BEQ_B(HOST_zero, temp1, 0) ); // opposite, gets inverted on short branches
	cache_addd( OP_AUIPC_U(temp1, 0) );
	cache_addd( OP_JALR_I(HOST_zero, temp1, 0) );
	unlock_temp(temp1);
	return (Bit8u *)(cache.pos-12);
}

// compare 32bit-register against zero and jump if value less/equal than zero
static const Bit8u* gen_create_branch_long_leqzero(HostReg reg) {
	HostReg temp1 = lock_temp();
	cache_addd( OP_ADDIW_I(temp1, reg, 0) );
	cache_addd( OP_BLT_B(HOST_zero, temp1, 0) ); // opposite, gets inverted on short branches
	cache_addd( OP_AUIPC_U(temp1, 0) );
	cache_addd( OP_JALR_I(HOST_zero, temp1, 0) );
	unlock_temp(temp1);
	return (Bit8u *)(cache.pos-12);
}

// calculate relative offset and fill it into the location pointed to by data
static void RV_MAYBE_INLINE gen_fill_branch(const Bit8u* data) {
	Bit64s off = (((Bit64s)(cache.pos)) - (Bit64s)(data+0));
	// default to long branches for now
	if (off >= -0x800L && off <= 0x7FFL) {
		// use XOR to also invert the condition
		((Bit32u *)data)[0] ^= MAKEOP_B(0x00, 0x1, HOST_zero, HOST_zero, off);
		((Bit32u *)data)[1] = OP_NOP();
		((Bit32u *)data)[2] = OP_NOP();
	} else {
		// advance data by 4, meaning subtract that from off
		off -= 4;

		if (off >= -0x80000000L && off <= 0x7FFFFFFFL) {
			// set the inverse branch distance
			((Bit32u *)data)[0] |= MAKEOP_B(0x00, 0x0, HOST_zero, HOST_zero, 12);
			// now fill in the relative branch
			((Bit32u *)data)[1] |= OP_AUIPC_U(HOST_zero, ((off+0x800)>>12));
			((Bit32u *)data)[2] |= OP_JALR_I(HOST_zero, HOST_zero, off);
		} else {
			gen_abort_helper("out-of-range branch");
		}
	}
}

// calculate long relative offset and fill it into the location pointed to by data
static void RV_MAYBE_INLINE gen_fill_branch_long(const Bit8u* data) {
	gen_fill_branch(data);
}

static void cache_block_closing(const uint8_t *block_start, Bitu block_size) {
	// FIXME: Work out how to invalidate the cache properly --GM
	asm volatile("fence\n");
	asm volatile("fence.i\n");
}

static void cache_block_before_close(void) { }

// move a 16bit constant value into dest_reg
// the upper 16bit of the destination register may be destroyed
static void RV_MAYBE_INLINE gen_mov_word_to_reg_imm(HostReg dest_reg,Bit16u imm) {
	gen_mov_dword_to_reg_imm(dest_reg, (Bit32u)imm);
}

// move an 8bit value from memory into dest_reg
// the upper 24bit of the destination register can be destroyed
// this function can use FC_OP1/FC_OP2 as dest_reg which are
// not directly byte-accessible on some architectures
static void RV_MAYBE_INLINE gen_mov_byte_to_reg_low_canuseword(HostReg dest_reg,void* data) {
	gen_mov_byte_to_reg_low(dest_reg, data);
}

// move an 8bit constant value into dest_reg
// the upper 24bit of the destination register can be destroyed
// this function does not use FC_OP1/FC_OP2 as dest_reg as these
// registers might not be directly byte-accessible on some architectures
static void gen_mov_byte_to_reg_low_imm(HostReg dest_reg, Bit8u imm) {
	cache_addd(OP_ADDIW_I(dest_reg, HOST_zero, imm));
}

// move an 8bit constant value into dest_reg
// the upper 24bit of the destination register can be destroyed
// this function can use FC_OP1/FC_OP2 as dest_reg which are
// not directly byte-accessible on some architectures
static void RV_MAYBE_INLINE gen_mov_byte_to_reg_low_imm_canuseword(HostReg dest_reg,Bit8u imm) {
	gen_mov_byte_to_reg_low_imm(dest_reg, imm);
}

// add a 32bit value from memory to a full register
static void gen_add(HostReg reg, void *op) {
	HostReg temp1 = lock_temp();
	gen_mov_word_to_reg(temp1, op, true);
	cache_addd(OP_ADDW_R(reg, reg, temp1));
	unlock_temp(temp1);
}

// effective address calculation, destination is dest_reg
// scale_reg is scaled by scale (scale_reg*(2^scale)) and
// added to dest_reg, then the immediate value is added
static void RV_MAYBE_INLINE gen_lea(HostReg dest_reg,HostReg scale_reg,Bitu scale,Bits imm) {
	if (scale) {
		HostReg temp1 = lock_temp();
		cache_addd(OP_SRLIW_I(temp1, scale_reg, scale));
		cache_addd(OP_ADDW_R(dest_reg, dest_reg, temp1));
		unlock_temp(temp1);
	} else {
		cache_addd(OP_ADDW_R(dest_reg, dest_reg, scale_reg));
	}
	gen_add_imm(dest_reg, imm);
}

// effective address calculation, destination is dest_reg
// dest_reg is scaled by scale (dest_reg*(2^scale)),
// then the immediate value is added
static void RV_MAYBE_INLINE gen_lea(HostReg dest_reg,Bitu scale,Bits imm) {
	if (scale) {
		cache_addd(OP_SRLIW_I(dest_reg, dest_reg, scale));
	}
	gen_add_imm(dest_reg, imm);
}


#ifdef DRC_FLAGS_INVALIDATION

// called when a call to a function can be replaced by a
// call to a simpler function
static void gen_fill_function_ptr(const Bit8u * pos,void* fct_ptr,Bitu flags_type) {
#ifdef DRC_FLAGS_INVALIDATION_DCODE
	Bit32u *data = (Bit32u *)pos;
	switch (flags_type) {
		case t_ADDb:
		case t_ADDw:
		case t_ADDd:
			data[0] = OP_ADDW_R(FC_RETOP, HOST_a1, HOST_a2);
			data[1] = OP_NOP();
			data[2] = OP_NOP();
			data[3] = OP_NOP();
			data[4] = OP_NOP();
			data[5] = OP_NOP();
			data[6] = OP_NOP();
			break;

		case t_XORb:
		case t_XORw:
		case t_XORd:
			data[0] = OP_XOR_R(FC_RETOP, HOST_a1, HOST_a2);
			data[1] = OP_NOP();
			data[2] = OP_NOP();
			data[3] = OP_NOP();
			data[4] = OP_NOP();
			data[5] = OP_NOP();
			data[6] = OP_NOP();
			break;

		default:
			// TODO: DRC_FLAGS_INVALIDATION_DCODE --GM
			printf("gen_fill_function_ptr %p %p %u\n", pos, fct_ptr, (Bit32u)flags_type);
#endif
			Bit64u ipos = (Bit64u)pos;
			*(Bit64u *)((ipos + 16 + 0x7) & ~0x7) = (Bit64u)fct_ptr;
#ifdef DRC_FLAGS_INVALIDATION_DCODE
	}
#endif
}

#endif
