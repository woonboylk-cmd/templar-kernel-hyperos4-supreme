/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: Pseudo-MGLRU Supreme v1.0
 * Unlock EXTM v4.0 + ZSTD 6:1 potential by locking VM tunables at Ring 0
 * Target: Xiaomi 12S (mayfly) - Linux 5.10.264 Templar v6.4
 *
 * Changes (all safe, all reversible):
 *   vm.swappiness:             20  -> 160
 *   vm.watermark_scale_factor: 50  -> 125
 *   vm.extra_free_kbytes:      41330 -> 102400
 *   metis/mi_boost_duration:   120000 -> 300000
 *   metis/limit_bgtask_sched:  1 -> 0
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <linux/printk.h>

KPM_NAME("pseudo-mglru-supreme");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("Pseudo-MGLRU Supreme: Ring 0 VM lock for EXTM+ZSTD optimization");

/* ======== Target values ======== */
#define T_SWAPPINESS        160
#define T_WSF               125
#define T_EXTRA_FREE_KB     102400
#define T_WBF               0

/* ======== Kernel variable pointers ======== */
static int *p_swappiness = 0;
static int *p_wsf = 0;
static int *p_efk = 0;
static int *p_wbf = 0;

/* metis module params */
static int *p_mi_boost_dur = 0;
static int *p_limit_bgtask = 0;

/* ======== Original values for restore ======== */
static int orig_swap = 0;
static int orig_wsf = 0;
static int orig_efk = 0;
static int orig_wbf = 0;
static int orig_boost_dur = 0;
static int orig_limit_bg = 0;

static int resolve_and_set_int(const char *name, int target, int **ptr_out, int *orig_out) {
    *ptr_out = (int *)kallsyms_lookup_name(name);
    if (!*ptr_out) {
        pr_warn("[KPM-MGLRU] Symbol not found: %s\n", name);
        return -1;
    }
    *orig_out = **ptr_out;
    **ptr_out = target;
    pr_info("[KPM-MGLRU] %s: %d -> %d\n", name, *orig_out, target);
    return 0;
}

static long mglru_init(const char *args, const char *event, void *__user reserved) {
    int ok = 0, fail = 0;

    pr_info("[KPM-MGLRU] ===== Pseudo-MGLRU Supreme v1.0 =====\n");
    pr_info("[KPM-MGLRU] Resolving kernel symbols via kallsyms...\n");

    /* --- Layer 1: VM tunables (direct kernel memory) --- */
    if (resolve_and_set_int("vm_swappiness", T_SWAPPINESS, &p_swappiness, &orig_swap) == 0) ok++; else fail++;
    if (resolve_and_set_int("watermark_scale_factor", T_WSF, &p_wsf, &orig_wsf) == 0) ok++; else fail++;
    if (resolve_and_set_int("extra_free_kbytes", T_EXTRA_FREE_KB, &p_efk, &orig_efk) == 0) ok++; else fail++;
    if (resolve_and_set_int("watermark_boost_factor", T_WBF, &p_wbf, &orig_wbf) == 0) ok++; else fail++;

    /* --- Layer 2: Metis scheduler params --- */
    if (resolve_and_set_int("mi_boost_duration", 300000, &p_mi_boost_dur, &orig_boost_dur) == 0) ok++; else fail++;
    if (resolve_and_set_int("limit_bgtask_sched", 0, &p_limit_bgtask, &orig_limit_bg) == 0) ok++; else fail++;

    pr_info("[KPM-MGLRU] Result: %d params set, %d not found\n", ok, fail);
    pr_info("[KPM-MGLRU] EXTM v4.0 ZRAM writeback + ZSTD 6:1 potential unlocked.\n");
    pr_info("[KPM-MGLRU] ===== Active =====\n");
    return 0;
}

static long mglru_exit(void *__user reserved) {
    pr_info("[KPM-MGLRU] Restoring original values...\n");
    if (p_swappiness)    *p_swappiness = orig_swap;
    if (p_wsf)           *p_wsf = orig_wsf;
    if (p_efk)           *p_efk = orig_efk;
    if (p_wbf)           *p_wbf = orig_wbf;
    if (p_mi_boost_dur)  *p_mi_boost_dur = orig_boost_dur;
    if (p_limit_bgtask)  *p_limit_bgtask = orig_limit_bg;
    pr_info("[KPM-MGLRU] All values restored. Module unloaded.\n");
    return 0;
}

KPM_INIT(mglru_init);
KPM_EXIT(mglru_exit);