/*
 * PIE-accelerated ChaCha20 block function for ESP32-P4.
 * Uses 128-bit SIMD to process all 4 columns/diagonals simultaneously.
 *
 * IMPORTANT: Uses esp.vadd.s32 (signed/wrapping), NOT esp.vadd.u32 (saturating).
 * ChaCha20 requires modular (wrapping) 32-bit addition.
 */

#include "sdkconfig.h"
#include "soc/soc_caps.h"

#if SOC_CPU_HAS_PIE

#include <stdint.h>

void chacha20_block_pie(uint8_t out[64], const uint32_t state[16])
{
    asm volatile (
        ".option push\n"
        ".option arch, +xesppie\n"

        /* Save pointers to callee-saved regs */
        "mv      s0, %[out]\n"
        "mv      s1, %[st]\n"

        /* Load state into Q registers */
        "mv      a2, s1\n"
        "esp.vld.128.ip q0, a2, 16\n"
        "esp.vld.128.ip q1, a2, 16\n"
        "esp.vld.128.ip q2, a2, 16\n"
        "esp.vld.128.ip q4, a2, 0\n"

        /* 10 double rounds */
        "li      a3, 10\n"
    "1:\n"

        /* ---- COLUMN ROUND ---- */
        "esp.vadd.s32 q0, q0, q1\n"
        "esp.xorq     q4, q4, q0\n"
        "li      a4, 16\n"
        "esp.movx.w.sar a4\n"
        "esp.vsl.32   q5, q4\n"
        "esp.vsr.u32  q4, q4\n"
        "esp.orq      q4, q4, q5\n"

        "esp.vadd.s32 q2, q2, q4\n"
        "esp.xorq     q1, q1, q2\n"
        "li      a4, 12\n"
        "esp.movx.w.sar a4\n"
        "esp.vsl.32   q5, q1\n"
        "li      a4, 20\n"
        "esp.movx.w.sar a4\n"
        "esp.vsr.u32  q1, q1\n"
        "esp.orq      q1, q1, q5\n"

        "esp.vadd.s32 q0, q0, q1\n"
        "esp.xorq     q4, q4, q0\n"
        "li      a4, 8\n"
        "esp.movx.w.sar a4\n"
        "esp.vsl.32   q5, q4\n"
        "li      a4, 24\n"
        "esp.movx.w.sar a4\n"
        "esp.vsr.u32  q4, q4\n"
        "esp.orq      q4, q4, q5\n"

        "esp.vadd.s32 q2, q2, q4\n"
        "esp.xorq     q1, q1, q2\n"
        "li      a4, 7\n"
        "esp.movx.w.sar a4\n"
        "esp.vsl.32   q5, q1\n"
        "li      a4, 25\n"
        "esp.movx.w.sar a4\n"
        "esp.vsr.u32  q1, q1\n"
        "esp.orq      q1, q1, q5\n"

        /* ---- DIAGONAL PERMUTATION ---- */
        "li      a4, 4\n"
        "esp.movx.w.sar.bytes a4\n"
        "esp.src.q    q1, q1, q1\n"
        "li      a4, 8\n"
        "esp.movx.w.sar.bytes a4\n"
        "esp.src.q    q2, q2, q2\n"
        "li      a4, 12\n"
        "esp.movx.w.sar.bytes a4\n"
        "esp.src.q    q4, q4, q4\n"

        /* ---- DIAGONAL ROUND ---- */
        "esp.vadd.s32 q0, q0, q1\n"
        "esp.xorq     q4, q4, q0\n"
        "li      a4, 16\n"
        "esp.movx.w.sar a4\n"
        "esp.vsl.32   q5, q4\n"
        "esp.vsr.u32  q4, q4\n"
        "esp.orq      q4, q4, q5\n"

        "esp.vadd.s32 q2, q2, q4\n"
        "esp.xorq     q1, q1, q2\n"
        "li      a4, 12\n"
        "esp.movx.w.sar a4\n"
        "esp.vsl.32   q5, q1\n"
        "li      a4, 20\n"
        "esp.movx.w.sar a4\n"
        "esp.vsr.u32  q1, q1\n"
        "esp.orq      q1, q1, q5\n"

        "esp.vadd.s32 q0, q0, q1\n"
        "esp.xorq     q4, q4, q0\n"
        "li      a4, 8\n"
        "esp.movx.w.sar a4\n"
        "esp.vsl.32   q5, q4\n"
        "li      a4, 24\n"
        "esp.movx.w.sar a4\n"
        "esp.vsr.u32  q4, q4\n"
        "esp.orq      q4, q4, q5\n"

        "esp.vadd.s32 q2, q2, q4\n"
        "esp.xorq     q1, q1, q2\n"
        "li      a4, 7\n"
        "esp.movx.w.sar a4\n"
        "esp.vsl.32   q5, q1\n"
        "li      a4, 25\n"
        "esp.movx.w.sar a4\n"
        "esp.vsr.u32  q1, q1\n"
        "esp.orq      q1, q1, q5\n"

        /* ---- UN-PERMUTE ---- */
        "li      a4, 12\n"
        "esp.movx.w.sar.bytes a4\n"
        "esp.src.q    q1, q1, q1\n"
        "li      a4, 8\n"
        "esp.movx.w.sar.bytes a4\n"
        "esp.src.q    q2, q2, q2\n"
        "li      a4, 4\n"
        "esp.movx.w.sar.bytes a4\n"
        "esp.src.q    q4, q4, q4\n"

        "addi    a3, a3, -1\n"
        "bnez    a3, 1b\n"

        /* === Final addition: reload original state === */
        "mv      a2, s1\n"
        "esp.vld.128.ip q5, a2, 16\n"
        "esp.vld.128.ip q6, a2, 16\n"
        "esp.vld.128.ip q7, a2, 16\n"
        "esp.vld.128.ip q3, a2, 0\n"

        "esp.vadd.s32 q0, q0, q5\n"
        "esp.vadd.s32 q1, q1, q6\n"
        "esp.vadd.s32 q2, q2, q7\n"
        "esp.vadd.s32 q4, q4, q3\n"

        /* === Store result === */
        "mv      a2, s0\n"
        "esp.vst.128.ip q0, a2, 16\n"
        "esp.vst.128.ip q1, a2, 16\n"
        "esp.vst.128.ip q2, a2, 16\n"
        "esp.vst.128.ip q4, a2, 0\n"

        ".option pop\n"

        : /* no C outputs */
        : [out] "r"(out), [st] "r"(state)
        : "a2", "a3", "a4", "s0", "s1", "memory"
    );
}

#endif /* SOC_CPU_HAS_PIE */
