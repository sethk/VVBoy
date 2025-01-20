#pragma once

#include "Types.hh"
#include "NVC.hh"

static const u_int32_t sign_bit32 = 0x80000000;
static const u_int64_t sign_bit64 = 0x8000000000000000;
static const u_int64_t sign_bits32to64 = 0xffffffff80000000;

inline static u_int32_t
cpu_extend8(u_int32_t s8)
{
	if ((s8 & 0x80) == 0x80)
		s8|= 0xffffff00;
	return s8;
}

inline static u_int32_t
cpu_extend9(u_int32_t s9)
{
	if ((s9 & 0x100) == 0x100)
		s9|= 0xfffffe00;
	return s9;
}

inline static u_int16_t
cpu_extend5to16(u_int16_t s5)
{
	if ((s5 & 0b10000) == 0b10000)
		s5|= 0xffe0;
	return s5;
}

// TODO: Possibly just assign signed type
inline static u_int32_t
cpu_extend5to32(u_int32_t s5)
{
	if ((s5 & 0b10000) == 0b10000)
		s5|= 0xffffffe0;
	return s5;
}

inline static u_int16_t
cpu_extend14to16(u_int16_t s14)
{
	if ((s14 & 0x2000) == 0x2000)
		s14|= 0xc000;
	return s14;
}

inline static u_int32_t
cpu_extend16(u_int32_t s16)
{
	if ((s16 & 0x8000) == 0x8000)
		s16|= 0xffff0000;
	return s16;
}

#   define CPU_MAX_PC (0xfffffffe)

union cpu_reg {u_int32_t u; int32_t s; float f; u_int16_t u16; int16_t s16; u_int8_t u8s[4];};
typedef union cpu_reg cpu_regs_t[32];

enum cpu_bcond : u_int8_t;

union cpu_inst
{
	u_int16_t ci_hwords[2];
	u_int32_t ci_word;
	struct
	{
		u_int16_t i_reg1 : 5;
		u_int16_t i_reg2 : 5;
		u_int16_t i_opcode : 6;
	} ci_i;
	struct
	{
		u_int16_t ii_imm5 : 5;
		u_int16_t ii_reg2 : 5;
		u_int16_t ii_opcode : 6;
	} ci_ii;
	struct
	{
		u_int16_t iii_disp9 : 9;
		u_int16_t iii_cond : 4;
		u_int16_t iii_opcode : 3;

		enum cpu_bcond GetCondition() const { return static_cast<cpu_bcond>(iii_cond); }
	} ci_iii;
	struct
	{
		u_int16_t iv_disp10 : 10;
		u_int16_t iv_opcode : 6;
		u_int16_t iv_disp16 : 16;
	} ci_iv;
	struct
	{
		u_int16_t v_reg1 : 5;
		u_int16_t v_reg2 : 5;
		u_int16_t v_opcode : 6;
		u_int16_t v_imm16;
	} ci_v;
	struct
	{
		u_int16_t vi_reg1 : 5;
		u_int16_t vi_reg2 : 5;
		u_int16_t vi_opcode : 6;
		int16_t vi_disp16;
	} ci_vi;
	struct
	{
		u_int16_t vii_reg1 : 5;
		u_int16_t vii_reg2 : 5;
		u_int16_t vii_opcode : 6;
		u_int16_t vii_rfu : 10;
		u_int16_t vii_subop : 6;
	};
};

enum cpu_opcode
{
	OP_MOV   = 0b000000,
	OP_ADD   = 0b000001,
	OP_SUB   = 0b000010,
	OP_CMP   = 0b000011,
	OP_SHL   = 0b000100,
	OP_SHR   = 0b000101,
	OP_JMP   = 0b000110,
	OP_SAR   = 0b000111,
	OP_MUL   = 0b001000,
	OP_DIV   = 0b001001,
	OP_MULU  = 0b001010,
	OP_DIVU  = 0b001011,
	OP_OR    = 0b001100,
	OP_AND   = 0b001101,
	OP_XOR   = 0b001110,
	OP_NOT   = 0b001111,
	OP_MOV2  = 0b010000,
	OP_ADD2  = 0b010001,
	OP_SETF  = 0b010010,
	OP_CMP2  = 0b010011,
	OP_SHL2  = 0b010100,
	OP_SHR2  = 0b010101,
	OP_CLI   = 0b010110,
	OP_SAR2  = 0b010111,
	OP_TRAP  = 0b011000,
	OP_RETI  = 0b011001,
	OP_HALT  = 0b011010,
	OP_LDSR  = 0b011100,
	OP_STSR  = 0b011101,
	OP_SEI   = 0b011110,
	OP_BSTR  = 0b011111,
	OP_BCOND = 0b100,
	OP_MOVEA = 0b101000,
	OP_ADDI  = 0b101001,
	OP_JR    = 0b101010,
	OP_JAL   = 0b101011,
	OP_ORI   = 0b101100,
	OP_ANDI  = 0b101101,
	OP_XORI  = 0b101110,
	OP_MOVHI = 0b101111,
	OP_LD_B  = 0b110000,
	OP_LD_H  = 0b110001,
	OP_LD_W  = 0b110011,
	OP_ST_B  = 0b110100,
	OP_ST_H  = 0b110101,
	OP_ST_W  = 0b110111,
	OP_IN_B  = 0b111000,
	OP_IN_H  = 0b111001,
	OP_CAXI  = 0b111010,
	OP_IN_W  = 0b111011,
	OP_OUT_B = 0b111100,
	OP_OUT_H = 0b111101,
	OP_FLOAT = 0b111110,
	OP_OUT_W = 0b111111
};

enum cpu_bcond : u_int8_t
{
	BCOND_BV  = 0b0000,
	BCOND_BL  = 0b0001,
	BCOND_BZ  = 0b0010,
	BCOND_BNH = 0b0011,
	BCOND_BN  = 0b0100,
	BCOND_BR  = 0b0101,
	BCOND_BLT = 0b0110,
	BCOND_BLE = 0b0111,
	BCOND_BNV = 0b1000,
	BCOND_BNC = 0b1001,
	BCOND_BNZ = 0b1010,
	BCOND_BH  = 0b1011,
	BCOND_BP  = 0b1100,
	BCOND_NOP = 0b1101,
	BCOND_BGE = 0b1110,
	BCOND_BGT = 0b1111,
};

enum cpu_bstr
{
	BSTR_SCH0BSU = 0b00000,
	BSTR_SCH0BSD = 0b00001,
	BSTR_SCH1BSU = 0b00010,
	BSTR_SCH1BSD = 0b00011,
	BSTR_ORBSU   = 0b01000,
	BSTR_ANDBSU  = 0b01001,
	BSTR_XORBSU  = 0b01010,
	BSTR_MOVBSU  = 0b01011,
	BSTR_ORNBSU  = 0b01100,
	BSTR_ANDNBSU = 0b01101,
	BSTR_XORNBSU = 0b01110,
	BSTR_NOTBSU  = 0b01111,
};

enum cpu_regid
{
	REGID_EIPC = 0,
	REGID_EIPSW = 1,
	REGID_FEPC = 2,
	REGID_FEPSW = 3,
	REGID_PSW = 5,
	REGID_CHCW = 24
};

enum cpu_chcw_flags
{
	// TODO: BIT()
	CPU_CHCW_ICC = (1 << 0),
	CPU_CHCW_ICE = (1 << 1)
};

enum float_subop
{
	FLOAT_CMPF_S =  0b000000,
	FLOAT_CVT_WS =  0b000010,
	FLOAT_CVT_SW =  0b000011,
	FLOAT_ADDF_S =  0b000100,
	FLOAT_SUBF_S =  0b000101,
	FLOAT_MULF_S =  0b000110,
	FLOAT_DIVF_S =  0b000111,
	FLOAT_XB =      0b001000,
	FLOAT_XH =      0b001001,
	FLOAT_TRNC_SW = 0b001011,
	FLOAT_MPYHW =   0b001100,
};

union cpu_psw
{
	u_int32_t psw_word;
	struct
	{
		u_int f_z : 1;
		u_int f_s : 1;
		u_int f_ov : 1;
		u_int f_cy : 1;
		u_int f_fpr : 1;
		u_int f_fud : 1;
		u_int f_fov : 1;
		u_int f_fzd : 1;
		u_int f_fiv : 1;
		u_int f_fro : 1;
		u_int reserved1 : 2;
		u_int f_id : 1;
		u_int f_ae : 1;
		u_int f_ep : 1;
		u_int f_np : 1;
		u_int f_i : 4;
	} psw_flags;
};

struct cpu_state
{
	cpu_regs_t cs_r;
	u_int32_t cs_pc;
	union cpu_psw cs_psw;
	struct cpu_ecr
	{
		int16_t ecr_eicc;
		int16_t ecr_fecc;
	} cs_ecr;
	u_int32_t cs_eipc;
	union cpu_psw cs_eipsw;
	u_int32_t cs_fepc;
	union cpu_psw cs_fepsw;
	u_int32_t cs_chcw;
};

extern struct cpu_state cpu_state;
extern u_int cpu_wait;
extern bool cpu_accurate_timing;

template<bool CheckedMem>
bool cpu_step(void);

void cpu_intr(nvc_intlevel level);

enum cpu_event
{
	CPU_EVENT_INTR_ENTER = EVENT_SUBSYS_BITS(EVENT_SUBSYS_CPU) | EVENT_WHICH_BITS(0),
	CPU_EVENT_INTR_RETURN = EVENT_SUBSYS_BITS(EVENT_SUBSYS_CPU) | EVENT_WHICH_BITS(1),
	CPU_EVENT_INTR_ENABLE = EVENT_SUBSYS_BITS(EVENT_SUBSYS_CPU) | EVENT_WHICH_BITS(2),
	CPU_EVENT_INTR_DISABLE = EVENT_SUBSYS_BITS(EVENT_SUBSYS_CPU) | EVENT_WHICH_BITS(3),
};

