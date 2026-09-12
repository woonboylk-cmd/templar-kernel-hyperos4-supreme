/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: HEO Scheduler TITAN Supreme v1.0
 * Ring 0 Dynamic CPU Scheduler & Core Affinity Enforcer
 * Target: Xiaomi 12S (mayfly) - Snapdragon 8+ Gen 1 (SM8475) - Linux 5.10.264
 * Architecture: KernelPatch (Ring 0 EL1)
 *
 * Hardware Topography (SM8475):
 *   CPUs 0-3: Cortex-A510 (LITTLE - 1.80 GHz, low-power background domain)
 *   CPUs 4-6: Cortex-A710 (MID    - 2.75 GHz, sustained compute domain)
 *   CPU 7:    Cortex-X2   (PRIME  - 3.20 GHz, ultra-responsive sovereign domain)
 *
 * Tri-Pillar Architecture:
 *   Pillar 1: CFS Real-Time Latency Tightening (latency=4ms, min_gran=0.75ms, wakeup_gran=1ms)
 *   Pillar 2: Xiaomi Metis Scheduler Governor Uncapping (mi_boost=300s, limit_bgtask=0)
 *   Pillar 3: Ring 0 Real-Time Task Steering Engine (select_task_rq hook):
 *             - Master & UI Critical (heo, surfaceflinger, RenderThread) -> Core 7 (Cortex-X2)
 *             - On-Device AI Engine  (llama-server, qwen, executor)     -> Cores 4-6 (Cortex-A710)
 *             - Background Bloatware (fb, ig, tiktok, miwallpaper)       -> Cores 0-2 (Cortex-A510)
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <hook.h>
#include <linux/printk.h>

KPM_NAME("heo-scheduler-titan");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity, OpenCode & vric");
KPM_DESCRIPTION("HEO Scheduler TITAN: Ring 0 Core Affinity & CFS Sovereign Governor");

/* ======== Target CFS Tunables ======== */
#define T_SCHED_LATENCY_NS         4000000U   /* 4ms (default 10ms) */
#define T_SCHED_MIN_GRAN_NS         750000U   /* 0.75ms (default 2ms) */
#define T_SCHED_WAKEUP_GRAN_NS     1000000U   /* 1ms (default 2ms) */
#define T_SCHED_MIGRATION_COST_NS   500000U   /* 0.5ms (default 0.25ms) */
#define T_MI_BOOST_DURATION         300000    /* 300s (default 120s) */
#define T_LIMIT_BGTASK_SCHED        0         /* 0 = Unrestricted background AI compute */

/* ======== Kernel Variable Pointers ======== */
static unsigned int *p_sched_latency = (void *)0;
static unsigned int *p_sched_min_gran = (void *)0;
static unsigned int *p_sched_wakeup_gran = (void *)0;
static unsigned int *p_sched_migration_cost = (void *)0;
static int *p_mi_boost_dur = (void *)0;
static int *p_limit_bgtask = (void *)0;

/* ======== Original Values for Safe Restore ======== */
static unsigned int orig_sched_latency = 0;
static unsigned int orig_sched_min_gran = 0;
static unsigned int orig_sched_wakeup_gran = 0;
static unsigned int orig_sched_migration_cost = 0;
static int orig_mi_boost_dur = 0;
static int orig_limit_bgtask = 0;

/* Function pointer to select_task_rq and __get_task_comm */
static void *p_select_task_rq = (void *)0;
static char *(*p_get_task_comm)(char *buf, unsigned long buf_size, void *tsk) = (void *)0;

/* Telemetry counters */
static volatile unsigned long stat_supreme_boosts = 0;
static volatile unsigned long stat_ai_steers = 0;
static volatile unsigned long stat_bloat_demotes = 0;

static int resolve_and_set_uint(const char *name, unsigned int target, unsigned int **ptr_out, unsigned int *orig_out) {
    *ptr_out = (unsigned int *)kallsyms_lookup_name(name);
    if (!*ptr_out) {
        pr_warn("[TITAN] Symbol not found: %s\n", name);
        return -1;
    }
    *orig_out = **ptr_out;
    **ptr_out = target;
    pr_info("[TITAN] %s: %u -> %u\n", name, *orig_out, target);
    return 0;
}

static int resolve_and_set_int(const char *name, int target, int **ptr_out, int *orig_out) {
    *ptr_out = (int *)kallsyms_lookup_name(name);
    if (!*ptr_out) {
        pr_warn("[TITAN] Symbol not found: %s\n", name);
        return -1;
    }
    *orig_out = **ptr_out;
    **ptr_out = target;
    pr_info("[TITAN] %s: %d -> %d\n", name, *orig_out, target);
    return 0;
}

/* Standalone string matcher (freestanding, zero-dependency) */
static inline int str_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    const char *h = haystack;
    while (*h) {
        const char *h_sub = h;
        const char *n_sub = needle;
        while (*h_sub && *n_sub && (*h_sub == *n_sub)) {
            h_sub++;
            n_sub++;
        }
        if (!*n_sub) return 1;
        h++;
    }
    return 0;
}

/*
 * Pillar 3: Real-Time Dynamic Task Steering Hook
 * Prototype in Linux 5.10 kernel/sched/core.c:
 * int select_task_rq(struct task_struct *p, int cpu, int sd_flags, int wake_flags);
 *
 * Arguments:
 *   args->arg0: struct task_struct *p
 *   args->arg1: int cpu
 *   args->arg2: int sd_flags
 *   args->arg3: int wake_flags
 *   args->ret:  chosen target cpu (0-7)
 */
static void after_select_task_rq(hook_fargs4_t *args, void *udata) {
    void *task = (void *)args->arg0;
    if (!task || !p_get_task_comm) return;

    int target_cpu = (int)args->ret;
    if (target_cpu < 0 || target_cpu > 7) return;

    char comm[16];
    p_get_task_comm(comm, sizeof(comm), task);
    comm[15] = '\0';

    /* 
     * Class 1: Background Bloatware Demotion
     * Strict isolation: Sát thủ chỉ được ngồi ghế đá A510 (Cores 0-2).
     * Shield Cortex-X2 Prime and A710 Mid cores from background pollution.
     */
    if (str_contains(comm, "facebook") ||
        str_contains(comm, "katana")   ||
        str_contains(comm, "orca")     ||
        str_contains(comm, "instagram")||
        str_contains(comm, "tiktok")   ||
        str_contains(comm, "zhiliao")  ||
        str_contains(comm, "miwallpap")||
        str_contains(comm, "earthSuper")) {
        if (target_cpu >= 3) {
            /* Demote to LITTLE core 0, 1, or 2 (strictly within background cpuset) */
            args->ret = (target_cpu % 3);
            stat_bloat_demotes++;
        }
        return;
    }

    /* 
     * Class 2: On-Device AI Engine Pinning (llama-server, Qwen, ExecuTorch)
     * Balanced throughput: Keep on Cortex-A710 Mid cores (4, 5, or 6).
     * Provides sustained 2.75 GHz without tripping Cortex-X2 thermal limits.
     */
    if (str_contains(comm, "llama") ||
        str_contains(comm, "qwen")  ||
        str_contains(comm, "executor")) {
        if (target_cpu < 4 || target_cpu == 7) {
            args->ret = 4 + (target_cpu % 3);
            stat_ai_steers++;
        }
        return;
    }

    /*
     * Class 3: Master & UI Critical Elevation
     * Sovereign privilege: HEO Master App, SurfaceFlinger, and RenderThread
     * upgraded from sluggish LITTLE cores (0-3) directly to Cortex-X2 (Core 7).
     * Zero-tolerance for UI frame drops and jitter.
     */
    if (str_contains(comm, "myapplicat") ||
        str_contains(comm, "heo")        ||
        str_contains(comm, "surfacefl")  ||
        str_contains(comm, "RenderThrea")||
        str_contains(comm, "composer-s")) {
        if (target_cpu < 4) {
            args->ret = 7; /* Cortex-X2 Prime (3.2 GHz) */
            stat_supreme_boosts++;
        }
        return;
    }
}

static long titan_init(const char *args, const char *event, void *reserved) {
    int ok = 0, fail = 0;

    pr_info("[TITAN] ===== HEO Scheduler TITAN Supreme v1.0 Initializing =====\n");
    pr_info("[TITAN] Target SoC: Snapdragon 8+ Gen 1 (SM8475) | KernelPatch EL1\n");

    /* --- Pillar 1: CFS Real-Time Latency Tightening --- */
    if (resolve_and_set_uint("sysctl_sched_latency", T_SCHED_LATENCY_NS, &p_sched_latency, &orig_sched_latency) == 0) ok++; else fail++;
    if (resolve_and_set_uint("sysctl_sched_min_granularity", T_SCHED_MIN_GRAN_NS, &p_sched_min_gran, &orig_sched_min_gran) == 0) ok++; else fail++;
    if (resolve_and_set_uint("sysctl_sched_wakeup_granularity", T_SCHED_WAKEUP_GRAN_NS, &p_sched_wakeup_gran, &orig_sched_wakeup_gran) == 0) ok++; else fail++;
    if (resolve_and_set_uint("sysctl_sched_migration_cost", T_SCHED_MIGRATION_COST_NS, &p_sched_migration_cost, &orig_sched_migration_cost) == 0) ok++; else fail++;

    /* --- Pillar 2: Xiaomi Metis Scheduler Governor Uncapping --- */
    if (resolve_and_set_int("mi_boost_duration", T_MI_BOOST_DURATION, &p_mi_boost_dur, &orig_mi_boost_dur) == 0) ok++; else fail++;
    if (resolve_and_set_int("limit_bgtask_sched", T_LIMIT_BGTASK_SCHED, &p_limit_bgtask, &orig_limit_bgtask) == 0) ok++; else fail++;

    /* --- Pillar 3: Ring 0 Real-Time Task Steering Engine --- */
    p_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    if (!p_get_task_comm) {
        pr_warn("[TITAN] Symbol __get_task_comm not found\n");
        fail++;
    } else {
        ok++;
    }

    p_select_task_rq = (void *)kallsyms_lookup_name("select_task_rq");
    if (p_select_task_rq && p_get_task_comm) {
        hook_err_t err = hook_wrap4(p_select_task_rq, (void *)0, after_select_task_rq, (void *)0);
        if (!err) {
            pr_info("[TITAN] Pillar 3 Hook select_task_rq ACTIVE (Core Supremacy Enabled)\n");
            ok++;
        } else {
            pr_warn("[TITAN] Hook select_task_rq failed: %d\n", err);
            fail++;
        }
    } else {
        pr_warn("[TITAN] Symbol select_task_rq not found in kallsyms\n");
        fail++;
    }

    pr_info("[TITAN] Result: %d components active, %d failed\n", ok, fail);
    pr_info("[TITAN] Cortex-X2 Sovereign Domain ACTIVE. Sát thủ demoted. Zero lag tolerated.\n");
    pr_info("[TITAN] ===== ACTIVE & OPERATIONAL =====\n");
    return 0;
}

static long titan_exit(void *reserved) {
    pr_info("[TITAN] Unloading HEO Scheduler TITAN Supreme...\n");
    pr_info("[TITAN] Telemetry: Supreme Boosts=%lu, AI Steers=%lu, Bloat Demotes=%lu\n",
            stat_supreme_boosts, stat_ai_steers, stat_bloat_demotes);

    /* Unhook Pillar 3 */
    if (p_select_task_rq) {
        hook_unwrap(p_select_task_rq, (void *)0, after_select_task_rq);
        pr_info("[TITAN] select_task_rq unhooked successfully.\n");
    }

    /* Restore Pillar 1 */
    if (p_sched_latency)        *p_sched_latency = orig_sched_latency;
    if (p_sched_min_gran)       *p_sched_min_gran = orig_sched_min_gran;
    if (p_sched_wakeup_gran)    *p_sched_wakeup_gran = orig_sched_wakeup_gran;
    if (p_sched_migration_cost) *p_sched_migration_cost = orig_sched_migration_cost;

    /* Restore Pillar 2 */
    if (p_mi_boost_dur)         *p_mi_boost_dur = orig_mi_boost_dur;
    if (p_limit_bgtask)         *p_limit_bgtask = orig_limit_bgtask;

    pr_info("[TITAN] All kernel tunables restored to baseline. Module unloaded cleanly.\n");
    return 0;
}

KPM_INIT(titan_init);
KPM_EXIT(titan_exit);
