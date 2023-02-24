
// Hacker Disassembler Engine 32bit
#pragma once

#include <stdint.h>

#define F_MODRM         0x00000001  // If instruction has a MOD byte
#define F_SIB           0x00000002
#define F_IMM8          0x00000004
#define F_IMM16         0x00000008
#define F_IMM32         0x00000010
#define _32_F_DISP8         0x00000020
#define _32_F_DISP16        0x00000040
#define _32_F_DISP32        0x00000080
#define _32_F_RELATIVE      0x00000100

#define F_2IMM16        0x00000800

#define F_ERROR         0x00001000
#define F_ERROR_OPCODE  0x00002000
#define F_ERROR_LENGTH  0x00004000
#define F_ERROR_LOCK    0x00008000
#define F_ERROR_OPERAND 0x00010000

#define F_PREFIX_REPNZ  0x01000000
#define F_PREFIX_REPX   0x02000000
#define F_PREFIX_REP    0x03000000
#define F_PREFIX_66     0x04000000
#define F_PREFIX_67     0x08000000
#define F_PREFIX_LOCK   0x10000000
#define F_PREFIX_SEG    0x20000000
#define _32_F_PREFIX_ANY    0x3F000000

#define PREFIX_SEGMENT_CS   0x2E
#define PREFIX_SEGMENT_SS   0x36
#define PREFIX_SEGMENT_DS   0x3E
#define PREFIX_SEGMENT_ES   0x26
#define PREFIX_SEGMENT_FS   0x64
#define PREFIX_SEGMENT_GS   0x65
#define PREFIX_LOCK         0xF0
#define PREFIX_REPNZ        0xF2
#define PREFIX_REPX         0xF3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

#pragma pack(push,1)
typedef struct
{
    uint8_t len;
    uint8_t p_rep;
    uint8_t p_lock;
    uint8_t p_seg;
    uint8_t p_66;
    uint8_t p_67;
    uint8_t opcode;
    uint8_t opcode2;
    uint8_t modrm;      // http://www.c-jump.com/CIS77/CPU/x86/X77_0060_mod_reg_r_m_byte.htm
    uint8_t modrm_mod;  // The two high MOD bits shifted down
    uint8_t modrm_reg;  // The three REG bits masked and shifted down
    uint8_t modrm_rm;   // The low 3 R/M bits masked
    uint8_t sib;
    uint8_t sib_scale;
    uint8_t sib_index;
    uint8_t sib_base;

    union
	{
        uint8_t imm8;
        uint16_t imm16;
        uint32_t imm32;
    } imm;

    union
	{
        uint8_t disp8;
        uint16_t disp16;
        uint32_t disp32;
    } disp;

    uint32_t flags;
} hde32s;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

UINT hde32_disasm(const PVOID code, hde32s *hs);

#ifdef __cplusplus
}
#endif
