/*
 * linux/arch/arm/kernel/idiv_emulate.c
 *
 * This code is based on swp_emulate.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Implements emulation of the SDIV/UDIV instructions. They are defined for
 * ARMv7-R and ARMv7-M profiles (in Thumb state only) and are UNDEFINED in the
 * ARMv7-A profile. SDIV/UDIV are present by default on Cortex-A15.
 *
 * This emulation allow using integer divide instructions in case hardware is
 * not presented
 *
 *  Syntax of SDIV/UDIV instructions: SDIV/UDIV<c> <Rd>,<Rn>,<Rm>
 *  Where: Rd  = the destination register.
 *	   Rn  = the register that contains the dividend.
 *	   Rm  = the register that contains the divisor.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/perf_event.h>

#include <asm/traps.h>
#include <asm/uaccess.h>

/*
 * Macros/defines for extracting register numbers from instruction.
 */
#define EXTRACT_REG_NUM(instruction, offset) \
	(((instruction) & (0xf << (offset))) >> (offset))

/*
 * Offsets for ARM mode
 */
#define RD_OFFSET  16
#define RN_OFFSET  0
#define RM_OFFSET  8

/*
 * Offsets for Thumb mode
 */
#define RD_T_OFFSET  8
#define RN_T_OFFSET  16
#define RM_T_OFFSET  0

#define TYPE_OF_DIV (1 << 21)

#if 0
static unsigned long sdivcounter;
static unsigned long udivcounter;
static pid_t         previous_pid;
#endif

#if 0
static int proc_read_status(char *page, char **start, off_t off, int count,
			    int *eof, void *data)
{
	char *p = page;
	int len;

	p += sprintf(p, "Emulated UDIV:\t\t%lu\n", udivcounter);
	p += sprintf(p, "Emulated SDIV:\t\t%lu\n", sdivcounter);
	if (previous_pid != 0)
		p += sprintf(p, "Last process:\t\t%d\n", previous_pid);

	len = (p - page) - off;
	if (len < 0)
		len = 0;

	*eof = (len <= count) ? 1 : 0;
	*start = page + off;

	return len;
}
#endif

#if 0
static u32 emulate_udiv(u32 n, u32 base)
{
	udivcounter++;

	return n/base;
}

static s32 emulate_sdiv(s32 n, s32  base)
{
	sdivcounter++;

	return n/base;
}
#endif

#define ARM_OPCODE_CONDITION_UNCOND 0xf
#define ARM_OPCODE_CONDTEST_FAIL   0
#define ARM_OPCODE_CONDTEST_PASS   1
#define ARM_OPCODE_CONDTEST_UNCOND 2

/*
 * condition code lookup table
 * index into the table is test code: EQ, NE, ... LT, GT, AL, NV
 *
 * bit position in short is condition code: NZCV
 */
static const unsigned short cc_map[16] = {
	0xF0F0,			/* EQ == Z set            */
	0x0F0F,			/* NE                     */
	0xCCCC,			/* CS == C set            */
	0x3333,			/* CC                     */
	0xFF00,			/* MI == N set            */
	0x00FF,			/* PL                     */
	0xAAAA,			/* VS == V set            */
	0x5555,			/* VC                     */
	0x0C0C,			/* HI == C set && Z clear */
	0xF3F3,			/* LS == C clear || Z set */
	0xAA55,			/* GE == (N==V)           */
	0x55AA,			/* LT == (N!=V)           */
	0x0A05,			/* GT == (!Z && (N==V))   */
	0xF5FA,			/* LE == (Z || (N!=V))    */
	0xFFFF,			/* AL always              */
	0			/* NV                     */
};

static int idiv_handler(struct pt_regs *regs, unsigned int instr)
{
	long dividend, divisor, dest; //, res;
#if 0
	perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS, 1, regs, regs->ARM_pc);
#endif

#if 0
	res = arm_check_condition(instr, regs->ARM_cpsr);

	switch (res) {
	case ARM_OPCODE_CONDTEST_PASS:
		break;
	case ARM_OPCODE_CONDTEST_FAIL:
		/* Condition failed - return to next instruction */
		regs->ARM_pc += 4;
		return 0;
	case ARM_OPCODE_CONDTEST_UNCOND:
		if (!thumb_mode(regs))
			return -EFAULT;
		break;
	default:
		return -EINVAL;
	}
#endif

	/*if ((instr >> 28 != 0xf) & (cc_map[instr >> 28] >> (regs->ARM_cpsr>>28))) {
		regs->ARM_pc += 4;
		return 0;
	}*/
	
#if 0

	if (current->pid != previous_pid) {
		pr_debug("\"%s\" (%ld) uses idiv instruction\n",
			 current->comm, (unsigned long)current->pid);
		previous_pid = current->pid;
	}

#endif

	if (!thumb_mode(regs)) {
		dividend = regs->uregs[EXTRACT_REG_NUM(instr, RN_OFFSET)];
		divisor = regs->uregs[EXTRACT_REG_NUM(instr, RM_OFFSET)];
		dest = EXTRACT_REG_NUM(instr, RD_OFFSET);
	} else {
		dividend = regs->uregs[EXTRACT_REG_NUM(instr, RN_T_OFFSET)];
		divisor = regs->uregs[EXTRACT_REG_NUM(instr, RM_T_OFFSET)];
		dest = EXTRACT_REG_NUM(instr, RD_T_OFFSET);
	}

/*
 * In an ARMv7-A profile implementation that supports the SDIV and UDIV
 * instructions, divide-by-zero always returns a zero result.
 * In fact, integer division emulation provided by gcc lib has already handle
 * division by zero case sending the signal to the caused process. Emulate this
 * behavior here as well.
 */
	if (!divisor) {
		siginfo_t info;

		info.si_code = FPE_INTDIV;
		info.si_signo = SIGFPE;
		info.si_errno = 0;

		arm_notify_die("Division by zero", regs, &info, 0, 0);

		goto out;
	}

	if (instr & TYPE_OF_DIV)
		regs->uregs[dest]=(u32)((u32)dividend/(u32)divisor);
	else
		regs->uregs[dest]=(s32)((s32)dividend/(s32)divisor);

	regs->ARM_pc += 4;

out:
	return 0;
}

static struct undef_hook idiv_hook = {
	.instr_mask = 0x0310f010,
	.instr_val  = 0x0310f010,
	.cpsr_mask  = MODE_MASK,
	.cpsr_val   = USR_MODE,
	.fn	    = idiv_handler
};

static int __init idiv_emulation_init(void)
{
#if 0
	struct proc_dir_entry *res;

	res = create_proc_entry("cpu/idiv_emulation", S_IRUGO, NULL);

	if (!res)
		return -ENOMEM;

	res->read_proc = proc_read_status;
#endif /* CONFIG_PROC_FS */

	pr_notice("Registering SDIV/UDIV emulation handler\n");

	register_undef_hook(&idiv_hook);

	return 0;
}

late_initcall(idiv_emulation_init);
