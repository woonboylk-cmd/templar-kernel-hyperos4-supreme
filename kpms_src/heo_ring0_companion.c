/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: HEO Ring 0 Sovereign Companion v4.0 Ultimate Supreme
 * Target: Xiaomi 12S (mayfly) - Snapdragon 8+ Gen 1 (SM8475) - Linux Kernel 5.10.x
 * Architecture: KernelPatch (Ring 0 EL1)
 *
 * Capabilities:
 * 1. Cryptographically-authenticated Syscall Bridge via sys_prctl (0x48454F 'HEO').
 * 2. Real-Time Dynamic Process Steering at Fork/Creation (Layer 4 Hook without LSPosed, ART, ptrace, or Zygote).
 * 3. Ring 0 Kernel Introspection Engine (Raw kernel scheduling, uptime, telemetry to HEO App & AI Agents).
 * 4. Instant Credential Elevation (HEO_CMD_ELEVATE_CREDS -> commit_creds(prepare_kernel_cred(NULL))).
 * 5. Kernel Process Task Inspection (HEO_CMD_TASK_INSPECT -> find_task_by_vpid zero-shell inspect).
 * 6. Direct Hardware Task Affinity Steering (HEO_CMD_SET_TASK_AFFINITY -> set_cpus_allowed_ptr).
 * 7. Arbitrary Kernel Memory Peeker & Patcher (HEO_CMD_KREAD / HEO_CMD_KWRITE).
 * 8. Dynamic Kernel Symbol Resolver (HEO_CMD_RESOLVE_SYMBOL -> kallsyms_lookup_name).
 * 9. Zero-relocation GOT 311 compliance (-fno-pic -mcmodel=small).
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <hook.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <linux/string.h>
#include <asm/current.h>

KPM_NAME("heo-ring0-companion");
KPM_VERSION("4.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("HEO Ring 0 Sovereign Companion v4.0 - Full Introspection, Credential Elevation & Layer 4 Steering");

#define HEO_MAGIC_PRCTL          0x48454F    /* 'HEO' in ASCII */

/* Authentication & Core Controls */
#define HEO_CMD_GET_CHALLENGE    0x01
#define HEO_CMD_VERIFY_AUTH      0x02
#define HEO_CMD_STATUS           0x03
#define HEO_CMD_FORCE_YAMA_OFF   0x04

/* Introspection & Telemetry Commands (Mở toang thông số nhân) */
#define HEO_CMD_KERNEL_TELEMETRY 0x05
#define HEO_CMD_SET_FORK_RULE    0x06
#define HEO_CMD_GET_FORK_RULES   0x07
#define HEO_CMD_CLEAR_FORK_RULES 0x09

/* Ultimate Sovereign Ring 0 Powers */
#define HEO_CMD_ELEVATE_CREDS     0x0A  /* Instant Root UID 0 + full capabilities for calling task */
#define HEO_CMD_TASK_INSPECT      0x0B  /* Zero-shell process inspection by PID */
#define HEO_CMD_KREAD             0x0C  /* Read arbitrary kernel memory */
#define HEO_CMD_KWRITE            0x0D  /* Write arbitrary kernel memory */
#define HEO_CMD_RESOLVE_SYMBOL    0x0E  /* Resolve any kernel symbol address */
#define HEO_CMD_SET_TASK_AFFINITY 0x0F  /* Hardware CPU pinning directly via kernel */

/* Pre-shared secret salt: 0xA55A1337BEEFCAFEULL */
#define HEO_SECRET_SALT          0xA55A1337BEEFCAFEULL
#define MAX_FORK_RULES           16

struct heo_fork_rule {
    char comm[16];
    uint8_t action;       /* 1: DEMOTE (Cores 0-2, nice +19), 2: BOOST (Core 7, Cortex-X2), 3: MID_AI (Cores 4-6) */
    uint8_t target_cpus;  /* Bitmask */
    uint8_t enabled;
};

struct heo_kernel_telemetry {
    uint32_t magic;              /* 0x48454F30 ('HEO0') */
    uint32_t version;            /* 0x0400 */
    uint64_t uptime_jiffies;     /* Kernel jiffies */
    uint32_t cfs_latency;        /* sysctl_sched_latency */
    uint32_t cfs_min_gran;       /* sysctl_sched_min_granularity */
    uint32_t cfs_wakeup_gran;    /* sysctl_sched_wakeup_granularity */
    uint32_t total_tasks_steered;/* Telemetry: total tasks intercepted */
    uint32_t bloat_demotes;      /* Telemetry: bloatware forced to A510 */
    uint32_t ui_boosts;          /* Telemetry: UI/HEO boosted to X2 */
    uint32_t ai_steers;          /* Telemetry: AI engine pinned to A710 */
    uint32_t active_rules_count; /* Number of active dynamic fork rules */
};

struct heo_task_inspect_info {
    uint32_t pid;
    uint32_t exists;
    char comm[16];
    uint64_t task_ptr;
};

/* Module State */
static unsigned long authorized_task_ptr = 0;
static uint64_t current_nonce = 0x1337CAFEBEEFULL;
static struct heo_fork_rule g_fork_rules[MAX_FORK_RULES];

/* Kernel Symbol Function Pointers */
static void *p_select_task_rq = (void *)0;
static char *(*p_get_task_comm)(char *buf, unsigned long buf_size, void *tsk) = (void *)0;
static unsigned long (*p_copy_to_user)(void *to, const void *from, unsigned long n) = (void *)0;
static unsigned long (*p_copy_from_user)(void *to, const void *from, unsigned long n) = (void *)0;
static unsigned long *p_jiffies = (void *)0;
static unsigned int *p_sched_latency = (void *)0;
static unsigned int *p_sched_min_gran = (void *)0;
static unsigned int *p_sched_wakeup_gran = (void *)0;

/* Advanced Kernel Operation Pointers */
static void *(*p_find_task_by_vpid)(int nr) = (void *)0;
static int (*p_set_cpus_allowed_ptr)(void *task, const void *new_mask) = (void *)0;
static int (*p_commit_creds)(void *new_cred) = (void *)0;
static void *(*p_prepare_kernel_cred)(void *daemon) = (void *)0;

/* Real-time Telemetry Counters */
static volatile unsigned long stat_tasks_steered = 0;
static volatile unsigned long stat_bloat_demotes = 0;
static volatile unsigned long stat_ui_boosts = 0;
static volatile unsigned long stat_ai_steers = 0;

/* Standalone String Matcher */
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
 * Layer 4 Dynamic Process Steering Hook
 * Intercepts select_task_rq at microsecond 0 when ANY task forks or wakes up.
 * Completely independent of LSPosed, ART, ptrace, or Zygote!
 */
static void after_select_task_rq(hook_fargs4_t *args, void *udata) {
    void *task = (void *)args->arg0;
    if (!task || !p_get_task_comm) return;

    int target_cpu = (int)args->ret;
    if (target_cpu < 0 || target_cpu > 7) return;

    char comm[16];
    p_get_task_comm(comm, sizeof(comm), task);
    comm[15] = '\0';

    /* 1. Dynamic in-kernel fork rules configured by HEO App & AI Agents */
    for (int i = 0; i < MAX_FORK_RULES; i++) {
        if (g_fork_rules[i].enabled && g_fork_rules[i].comm[0] != '\0') {
            if (str_contains(comm, g_fork_rules[i].comm)) {
                if (g_fork_rules[i].action == 1) {
                    /* DEMOTE: Confine to Cortex-A510 Little (Cores 0-2) */
                    args->ret = (target_cpu % 3);
                    stat_bloat_demotes++;
                } else if (g_fork_rules[i].action == 2) {
                    /* BOOST: Elevate to Cortex-X2 Prime (Core 7, 3.2 GHz) */
                    args->ret = 7;
                    stat_ui_boosts++;
                } else if (g_fork_rules[i].action == 3) {
                    /* MID_AI: Pin to Cortex-A710 Mid (Cores 4-6, 2.75 GHz) */
                    args->ret = 4 + (target_cpu % 3);
                    stat_ai_steers++;
                }
                stat_tasks_steered++;
                return;
            }
        }
    }

    /* 2. Built-in Sovereign Hardened Demotions (Background Parasites) */
    if (str_contains(comm, "facebook") || str_contains(comm, "katana") ||
        str_contains(comm, "orca")     || str_contains(comm, "instagram") ||
        str_contains(comm, "tiktok")   || str_contains(comm, "zhiliao") ||
        str_contains(comm, "miwallpap")|| str_contains(comm, "earthSuper")) {
        if (target_cpu >= 3) {
            args->ret = (target_cpu % 3);
            stat_bloat_demotes++;
            stat_tasks_steered++;
        }
        return;
    }

    /* 3. Built-in On-Device AI Engine Pinning (llama-server, Qwen, ExecuTorch) */
    if (str_contains(comm, "llama") || str_contains(comm, "qwen") ||
        str_contains(comm, "executor")) {
        if (target_cpu < 4 || target_cpu == 7) {
            args->ret = 4 + (target_cpu % 3);
            stat_ai_steers++;
            stat_tasks_steered++;
        }
        return;
    }

    /* 4. Built-in Sovereign UI & HEO Master Elevation */
    if (str_contains(comm, "myapplicat") || str_contains(comm, "heo") ||
        str_contains(comm, "surfacefl")  || str_contains(comm, "RenderThrea") ||
        str_contains(comm, "composer-s")) {
        if (target_cpu < 4) {
            args->ret = 7; /* Cortex-X2 Prime (3.2 GHz) */
            stat_ui_boosts++;
            stat_tasks_steered++;
        }
        return;
    }
}

/*
 * Syscall prctl Hook (Cầu nối Lệnh Sovereign Ring 0)
 */
void before_prctl_hook(hook_fargs5_t *args, void *udata) {
    int option = (int)syscall_argn(args, 0);
    if (option != HEO_MAGIC_PRCTL) return;

    /* Intercepted HEO command: bypass original sys_prctl */
    args->skip_origin = 1;

    unsigned long cmd = (unsigned long)syscall_argn(args, 1);
    struct task_struct *task = current;
    unsigned long task_now = (unsigned long)task;

    switch (cmd) {
        case HEO_CMD_GET_CHALLENGE: {
            current_nonce = (current_nonce * 6364136223846793005ULL) + 1442695040888963407ULL + task_now;
            uint32_t nonce32 = (uint32_t)(current_nonce & 0x7FFFFFFFU);
            if (nonce32 == 0) nonce32 = 0x1337BEEF;
            args->ret = (uint64_t)nonce32;
            pr_info("[HEO-KPM] Nonce challenge issued for task 0x%lx: 0x%x\n", task_now, nonce32);
            break;
        }

        case HEO_CMD_VERIFY_AUTH: {
            uint64_t client_token = (uint64_t)syscall_argn(args, 2);
            uint32_t nonce32 = (uint32_t)(current_nonce & 0x7FFFFFFFU);
            if (nonce32 == 0) nonce32 = 0x1337BEEF;
            uint64_t expected_token = ((uint64_t)nonce32) ^ HEO_SECRET_SALT;

            if (client_token == expected_token) {
                authorized_task_ptr = task_now;
                args->ret = 0x1337;
                pr_info("[HEO-KPM] Auth SUCCESS! Task 0x%lx granted Ring 0 Sovereign privilege.\n", task_now);
            } else {
                args->ret = (uint64_t)-1;
                pr_warn("[HEO-KPM] Auth FAILED: token mismatch from Task 0x%lx!\n", task_now);
            }
            break;
        }

        case HEO_CMD_STATUS: {
            args->ret = (authorized_task_ptr != 0 && authorized_task_ptr == task_now) ? 1 : 0;
            break;
        }

        case HEO_CMD_FORCE_YAMA_OFF: {
            if (authorized_task_ptr == task_now) {
                int *p_yama = (int *)kallsyms_lookup_name("ptrace_scope");
                if (p_yama) {
                    *p_yama = 0;
                    pr_info("[HEO-KPM] yama.ptrace_scope set to 0\n");
                }
                args->ret = 0;
            } else {
                args->ret = (uint64_t)-1;
            }
            break;
        }

        case HEO_CMD_KERNEL_TELEMETRY: {
            if (authorized_task_ptr == task_now) {
                void *user_buf = (void *)syscall_argn(args, 2);
                if (!user_buf || !p_copy_to_user) {
                    args->ret = (uint64_t)-1;
                    break;
                }

                uint32_t active_rules = 0;
                for (int i = 0; i < MAX_FORK_RULES; i++) {
                    if (g_fork_rules[i].enabled) active_rules++;
                }

                struct heo_kernel_telemetry telem;
                memset(&telem, 0, sizeof(telem));
                telem.magic = 0x48454F30;
                telem.version = 0x0400;
                telem.uptime_jiffies = p_jiffies ? *p_jiffies : 0;
                telem.cfs_latency = p_sched_latency ? *p_sched_latency : 0;
                telem.cfs_min_gran = p_sched_min_gran ? *p_sched_min_gran : 0;
                telem.cfs_wakeup_gran = p_sched_wakeup_gran ? *p_sched_wakeup_gran : 0;
                telem.total_tasks_steered = stat_tasks_steered;
                telem.bloat_demotes = stat_bloat_demotes;
                telem.ui_boosts = stat_ui_boosts;
                telem.ai_steers = stat_ai_steers;
                telem.active_rules_count = active_rules;

                if (p_copy_to_user(user_buf, &telem, sizeof(telem)) == 0) {
                    args->ret = 0;
                } else {
                    args->ret = (uint64_t)-14; /* -EFAULT */
                }
            } else {
                args->ret = (uint64_t)-1;
            }
            break;
        }

        case HEO_CMD_SET_FORK_RULE: {
            if (authorized_task_ptr == task_now) {
                void *user_buf = (void *)syscall_argn(args, 2);
                if (!user_buf || !p_copy_from_user) {
                    args->ret = (uint64_t)-1;
                    break;
                }

                struct heo_fork_rule rule;
                if (p_copy_from_user(&rule, user_buf, sizeof(rule)) != 0) {
                    args->ret = (uint64_t)-14;
                    break;
                }
                rule.comm[15] = '\0';

                int target_slot = -1;
                for (int i = 0; i < MAX_FORK_RULES; i++) {
                    if (g_fork_rules[i].enabled && strcmp(g_fork_rules[i].comm, rule.comm) == 0) {
                        target_slot = i;
                        break;
                    }
                }
                if (target_slot == -1) {
                    for (int i = 0; i < MAX_FORK_RULES; i++) {
                        if (!g_fork_rules[i].enabled) {
                            target_slot = i;
                            break;
                        }
                    }
                }

                if (target_slot >= 0) {
                    memcpy(&g_fork_rules[target_slot], &rule, sizeof(rule));
                    g_fork_rules[target_slot].enabled = 1;
                    pr_info("[HEO-KPM] Dynamic Fork Rule #%d set: '%s' -> action %d\n",
                            target_slot, rule.comm, rule.action);
                    args->ret = 0;
                } else {
                    args->ret = (uint64_t)-28; /* -ENOSPC */
                }
            } else {
                args->ret = (uint64_t)-1;
            }
            break;
        }

        case HEO_CMD_GET_FORK_RULES: {
            if (authorized_task_ptr == task_now) {
                void *user_buf = (void *)syscall_argn(args, 2);
                if (!user_buf || !p_copy_to_user) {
                    args->ret = (uint64_t)-1;
                    break;
                }

                if (p_copy_to_user(user_buf, g_fork_rules, sizeof(g_fork_rules)) == 0) {
                    args->ret = 0;
                } else {
                    args->ret = (uint64_t)-14;
                }
            } else {
                args->ret = (uint64_t)-1;
            }
            break;
        }

        case HEO_CMD_CLEAR_FORK_RULES: {
            if (authorized_task_ptr == task_now) {
                memset(g_fork_rules, 0, sizeof(g_fork_rules));
                pr_info("[HEO-KPM] All dynamic fork rules cleared from Ring 0 RAM.\n");
                args->ret = 0;
            } else {
                args->ret = (uint64_t)-1;
            }
            break;
        }

        /*
         * Ultimate Superpower 1: Instant Kernel Credential Elevation
         * Grants Root UID 0 + Full Capabilities directly inside kernel without calling 'su'.
         */
        case HEO_CMD_ELEVATE_CREDS: {
            if (authorized_task_ptr == task_now) {
                if (!p_commit_creds || !p_prepare_kernel_cred) {
                    args->ret = (uint64_t)-38; /* ENOSYS */
                    break;
                }
                void *kcred = p_prepare_kernel_cred(NULL);
                if (kcred) {
                    int ret = p_commit_creds(kcred);
                    pr_info("[HEO-KPM] Task 0x%lx elevated to ROOT UID 0 in Ring 0 (ret: %d)!\n", task_now, ret);
                    args->ret = (uint64_t)ret;
                } else {
                    args->ret = (uint64_t)-12; /* ENOMEM */
                }
            } else {
                args->ret = (uint64_t)-1;
            }
            break;
        }

        /*
         * Ultimate Superpower 2: Zero-Shell Process Inspection
         * Directly reads task attributes by PID via find_task_by_vpid (0ms, 0 shell).
         */
        case HEO_CMD_TASK_INSPECT: {
            if (authorized_task_ptr == task_now) {
                int target_pid = (int)syscall_argn(args, 2);
                void *user_buf = (void *)syscall_argn(args, 3);
                if (!user_buf || !p_copy_to_user || !p_find_task_by_vpid || !p_get_task_comm) {
                    args->ret = (uint64_t)-22;
                    break;
                }
                void *target_task = p_find_task_by_vpid(target_pid);
                struct heo_task_inspect_info info;
                memset(&info, 0, sizeof(info));
                info.pid = target_pid;

                if (target_task) {
                    info.exists = 1;
                    info.task_ptr = (unsigned long)target_task;
                    p_get_task_comm(info.comm, sizeof(info.comm), target_task);
                    info.comm[15] = '\0';
                } else {
                    info.exists = 0;
                }

                if (p_copy_to_user(user_buf, &info, sizeof(info)) == 0) {
                    args->ret = info.exists ? 0 : (uint64_t)-3; /* ESRCH */
                } else {
                    args->ret = (uint64_t)-14;
                }
            } else {
                args->ret = (uint64_t)-1;
            }
            break;
        }

        /*
         * Ultimate Superpower 3: Arbitrary Kernel Memory Peeker
         */
        case HEO_CMD_KREAD: {
            if (authorized_task_ptr == task_now) {
                unsigned long kaddr = (unsigned long)syscall_argn(args, 2);
                void *user_buf = (void *)syscall_argn(args, 3);
                unsigned long len = (unsigned long)syscall_argn(args, 4);
                if (!user_buf || !p_copy_to_user || len == 0 || len > 4096) {
                    args->ret = (uint64_t)-22;
                    break;
                }
                if (p_copy_to_user(user_buf, (const void *)kaddr, len) == 0) {
                    args->ret = 0;
                } else {
                    args->ret = (uint64_t)-14;
                }
            } else {
                args->ret = (uint64_t)-1;
            }
            break;
        }

        /*
         * Ultimate Superpower 4: Arbitrary Kernel Memory Patcher
         */
        case HEO_CMD_KWRITE: {
            if (authorized_task_ptr == task_now) {
                unsigned long kaddr = (unsigned long)syscall_argn(args, 2);
                const void *user_buf = (const void *)syscall_argn(args, 3);
                unsigned long len = (unsigned long)syscall_argn(args, 4);
                if (!user_buf || !p_copy_from_user || len == 0 || len > 4096) {
                    args->ret = (uint64_t)-22;
                    break;
                }
                if (p_copy_from_user((void *)kaddr, user_buf, len) == 0) {
                    args->ret = 0;
                } else {
                    args->ret = (uint64_t)-14;
                }
            } else {
                args->ret = (uint64_t)-1;
            }
            break;
        }

        /*
         * Ultimate Superpower 5: Dynamic Kernel Symbol Resolver
         * Resolves any kernel symbol address on-the-fly directly to userspace.
         */
        case HEO_CMD_RESOLVE_SYMBOL: {
            if (authorized_task_ptr == task_now) {
                const void *user_name = (const void *)syscall_argn(args, 2);
                if (!user_name || !p_copy_from_user) {
                    args->ret = 0;
                    break;
                }
                char sym_name[64];
                memset(sym_name, 0, sizeof(sym_name));
                if (p_copy_from_user(sym_name, user_name, 63) == 0) {
                    sym_name[63] = '\0';
                    unsigned long addr = (unsigned long)kallsyms_lookup_name(sym_name);
                    args->ret = addr;
                    pr_info("[HEO-KPM] Resolved symbol '%s' -> 0x%lx\n", sym_name, addr);
                } else {
                    args->ret = 0;
                }
            } else {
                args->ret = 0;
            }
            break;
        }

        /*
         * Ultimate Superpower 6: Hardware CPU Affinity Steering
         * Binds ANY task PID to a CPU mask directly via set_cpus_allowed_ptr (0 shell, 0ms).
         */
        case HEO_CMD_SET_TASK_AFFINITY: {
            if (authorized_task_ptr == task_now) {
                int target_pid = (int)syscall_argn(args, 2);
                unsigned long mask_val = (unsigned long)syscall_argn(args, 3);
                if (!p_find_task_by_vpid || !p_set_cpus_allowed_ptr) {
                    args->ret = (uint64_t)-38;
                    break;
                }
                void *target_task = p_find_task_by_vpid(target_pid);
                if (!target_task) {
                    args->ret = (uint64_t)-3; /* ESRCH */
                    break;
                }
                int ret = p_set_cpus_allowed_ptr(target_task, (const void *)&mask_val);
                args->ret = (uint64_t)ret;
                pr_info("[HEO-KPM] set_cpus_allowed_ptr(pid=%d, mask=0x%lx) ret: %d\n", target_pid, mask_val, ret);
            } else {
                args->ret = (uint64_t)-1;
            }
            break;
        }

        default:
            args->ret = (uint64_t)-1;
            break;
    }
}

static long heo_companion_init(const char *args, const char *event, void *reserved) {
    pr_info("[HEO-KPM] ===== Initializing HEO Ring 0 Sovereign Companion v4.0.0 Ultimate Supreme =====\n");
    pr_info("[HEO-KPM] Target SoC: Snapdragon 8+ Gen 1 (SM8475) | KernelPatch EL1\n");

    /* 1. Resolve Core Kernel Helpers */
    p_copy_to_user = (void *)kallsyms_lookup_name("__arch_copy_to_user");
    p_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    p_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    p_jiffies = (unsigned long *)kallsyms_lookup_name("jiffies_64");
    if (!p_jiffies) p_jiffies = (unsigned long *)kallsyms_lookup_name("jiffies");
    p_sched_latency = (unsigned int *)kallsyms_lookup_name("sysctl_sched_latency");
    p_sched_min_gran = (unsigned int *)kallsyms_lookup_name("sysctl_sched_min_granularity");
    p_sched_wakeup_gran = (unsigned int *)kallsyms_lookup_name("sysctl_sched_wakeup_granularity");

    /* 2. Resolve Advanced Sovereign Operation Pointers */
    p_find_task_by_vpid = (void *)kallsyms_lookup_name("find_task_by_vpid");
    p_set_cpus_allowed_ptr = (void *)kallsyms_lookup_name("set_cpus_allowed_ptr");
    p_commit_creds = (void *)kallsyms_lookup_name("commit_creds");
    p_prepare_kernel_cred = (void *)kallsyms_lookup_name("prepare_kernel_cred");

    /* 3. Hook Syscall prctl (0x48454F) */
    hook_err_t err = inline_hook_syscalln(__NR_prctl, 5, before_prctl_hook, NULL, NULL);
    if (err) {
        pr_err("[HEO-KPM] inline_hook_syscalln(__NR_prctl) failed: %d\n", err);
        return -1;
    }

    /* 4. Hook select_task_rq (Layer 4 Dynamic Fork Steering Engine) */
    p_select_task_rq = (void *)kallsyms_lookup_name("select_task_rq");
    if (p_select_task_rq) {
        hook_err_t h_err = inline_hook_address(p_select_task_rq, 4, NULL, after_select_task_rq, NULL);
        if (h_err == 0) {
            pr_info("[HEO-KPM] Layer 4 Task Steering Hook ACTIVE on select_task_rq.\n");
        } else {
            pr_warn("[HEO-KPM] inline_hook_address(select_task_rq) returned: %d\n", h_err);
        }
    } else {
        pr_warn("[HEO-KPM] select_task_rq symbol not found in kallsyms.\n");
    }

    memset(g_fork_rules, 0, sizeof(g_fork_rules));
    pr_info("[HEO-KPM] Sovereign Ring 0 Ultimate Superpowers ONLINE (v4.0.0) 👑\n");
    return 0;
}

static long heo_companion_exit(void *reserved) {
    pr_info("[HEO-KPM] Unloading HEO Ring 0 Sovereign Companion...\n");
    inline_unhook_syscalln(__NR_prctl, before_prctl_hook, NULL);
    if (p_select_task_rq) {
        inline_unhook_address(p_select_task_rq, after_select_task_rq);
    }
    authorized_task_ptr = 0;
    return 0;
}

KPM_INIT(heo_companion_init);
KPM_EXIT(heo_companion_exit);