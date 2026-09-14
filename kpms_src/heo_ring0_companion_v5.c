/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: HEO Ring 0 Sovereign Companion v5.0 — Merged Hardened Edition
 * Target: Xiaomi 12S (mayfly) - Snapdragon 8+ Gen 1 (SM8475) - Linux 5.10.x
 *
 * Features:
 *   [A] All-in-one: steering + creds + introspection + file spoofer
 *   [B] Fixed 5 spoofer bugs (openat2, readlinkat, relative path, exact match, camera by comm)
 *   [C] Symbol fallback chain + NULL checks
 *   [D] KREAD dùng copy_from_kernel_nofault (không panic)
 *   [E] Camera whitelist bằng get_task_comm() — không deref offset thô
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <hook.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("heo-ring0-companion");
KPM_VERSION("5.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("HEO Ring 0 v5.1 — Merged hardened: steering + spoof + introspection");

/* KPM-safe memory helpers: avoids emitting BL memcpy/memset which are
 * not exported in KernelPatch symbol table (causes ENOENT / rc=-2).
 * These are inlined by the compiler, zero external symbol dependency. */
static __always_inline void *kpm_memset(void *dst, int c, unsigned long n)
{
    unsigned char *p = (unsigned char *)dst;
    while (n--) *p++ = (unsigned char)c;
    return dst;
}

static __always_inline void *kpm_memcpy(void *dst, const void *src, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

/* ==========================================================================
 * SECTION 1: CONSTANTS & STRUCTS
 * ========================================================================== */

#define HEO_MAGIC_PRCTL          0x48454F

/* Auth & control */
#define HEO_CMD_GET_CHALLENGE    0x01
#define HEO_CMD_VERIFY_AUTH      0x02
#define HEO_CMD_STATUS           0x03
#define HEO_CMD_FORCE_YAMA_OFF   0x04

/* Introspection & telemetry */
#define HEO_CMD_KERNEL_TELEMETRY 0x05
#define HEO_CMD_SET_FORK_RULE    0x06
#define HEO_CMD_GET_FORK_RULES   0x07
#define HEO_CMD_CLEAR_FORK_RULES 0x09

/* Sovereign powers */
#define HEO_CMD_ELEVATE_CREDS     0x0A
#define HEO_CMD_TASK_INSPECT      0x0B
#define HEO_CMD_KREAD             0x0C
#define HEO_CMD_KWRITE            0x0D
#define HEO_CMD_RESOLVE_SYMBOL    0x0E
#define HEO_CMD_SET_TASK_AFFINITY 0x0F

/* Spoofer control */
#define HEO_CMD_SPOOF_ENABLE      0x10
#define HEO_CMD_SPOOF_DISABLE     0x11
#define HEO_CMD_SPOOF_STATUS      0x12

#define HEO_SECRET_SALT          0xA55A1337BEEFCAFEULL
#define MAX_FORK_RULES           16

#define SPOOF_PATH       "/data/adb/p11.prop"
#define SPOOF_PATH_LEN   18
#define FAKE_PATH        "/system/build.prop"
#define FAKE_PATH_LEN    19

#ifndef __NR_openat
#define __NR_openat      56
#endif
#ifndef __NR_openat2
#define __NR_openat2     437
#endif
#ifndef __NR_readlinkat
#define __NR_readlinkat  78
#endif

struct heo_fork_rule {
    char     comm[16];
    uint8_t  action;
    uint8_t  target_cpus;
    uint8_t  enabled;
};

struct heo_kernel_telemetry {
    uint32_t magic;
    uint32_t version;
    uint64_t uptime_jiffies;
    uint32_t cfs_latency;
    uint32_t cfs_min_gran;
    uint32_t cfs_wakeup_gran;
    uint32_t total_tasks_steered;
    uint32_t bloat_demotes;
    uint32_t ui_boosts;
    uint32_t ai_steers;
    uint32_t active_rules_count;
    uint32_t spoof_enabled;
    uint32_t spoof_hits;
};

struct heo_task_inspect_info {
    uint32_t pid;
    uint32_t exists;
    char     comm[16];
    uint64_t task_ptr;
};

/* ==========================================================================
 * SECTION 2: GLOBAL STATE & SYMBOLS
 * ========================================================================== */

static unsigned long authorized_task_ptr = 0;
static uint64_t      current_nonce = 0x1337CAFEBEEFULL;
static struct heo_fork_rule g_fork_rules[MAX_FORK_RULES];
static int g_comm_offset = -1;
static volatile int g_spoof_enabled = 1;
static volatile unsigned long g_spoof_hits = 0;

/* Scheduler / CFS */
static void *p_select_task_rq = 0;
static unsigned long *p_jiffies = 0;
static unsigned int *p_sched_latency = 0;
static unsigned int *p_sched_min_gran = 0;
static unsigned int *p_sched_wakeup_gran = 0;
static unsigned int *p_sched_migration_cost = 0;
static unsigned int orig_sched_latency = 0;
static unsigned int orig_sched_min_gran = 0;
static unsigned int orig_sched_wakeup_gran = 0;
static unsigned int orig_sched_migration_cost = 0;

/* Advanced ops */
static void *(*p_find_task_by_vpid)(int) = 0;
static int  (*p_set_cpus_allowed_ptr)(void *, const void *) = 0;
static int  (*p_commit_creds)(void *) = 0;
static void *(*p_prepare_kernel_cred)(void *) = 0;
static char *(*p_get_task_comm)(char *, unsigned long, void *) = 0;

/* User copy */
static unsigned long (*p_ctu)(void *, const void *, unsigned long) = 0;
static unsigned long (*p_cfu)(void *, const void *, unsigned long) = 0;

/* Kernel-safe read — chống panic */
static int (*p_knofault)(void *dst, const void *src, size_t n) = 0;

/* ==========================================================================
 * SECTION 3: HELPERS (không deref kernel ptr)
 * ========================================================================== */

static size_t s_len(const char *s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static int s_cmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static int s_ncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (unsigned char)a[i] - (unsigned char)b[i];
        if (!a[i]) return 0;
    }
    return 0;
}

static int starts_with(const char *p, const char *pfx) {
    while (*pfx) { if (*p++ != *pfx++) return 0; }
    return 1;
}

/* Tìm word boundary an toàn: "vendor" chỉ match khi đứng riêng
 * (đứng sau '/' hoặc đầu chuỗi, và kết thúc bởi '/' hoặc '\0') */
static int contains_path_word(const char *path, const char *word) {
    size_t wl = s_len(word);
    if (wl == 0) return 0;
    const char *p = path;
    while (*p) {
        if ((p == path || p[-1] == '/') && s_ncmp(p, word, wl) == 0 &&
            (p[wl] == '/' || p[wl] == '\0'))
            return 1;
        p++;
    }
    return 0;
}

static int ends_with_build_prop(const char *p) {
    size_t n = s_len(p);
    if (n >= 11 && s_ncmp(p + n - 10, "build.prop", 10) == 0 && p[n-11] == '/')
        return 1;
    if (n == 10 && s_ncmp(p, "build.prop", 10) == 0)
        return 1;
    return 0;
}

static int is_proc_fd_path(const char *p) {
    if (!starts_with(p, "/proc/")) return 0;
    while (*p) {
        if (p[0]=='/' && p[1]=='f' && p[2]=='d' && p[3]=='/') return 1;
        p++;
    }
    return 0;
}

/* ==========================================================================
 * SECTION 4: SPOOF DECISION LOGIC (fixed 5 bugs)
 * ========================================================================== */

/* Bug #4 fix: exact suffix match, có boundary */
static int path_excluded(const char *p) {
    /* vendor / odm / my_product / apex / data / sdcard — không spoof */
    if (contains_path_word(p, "vendor"))     return 1;
    if (contains_path_word(p, "odm"))        return 1;
    if (contains_path_word(p, "my_product")) return 1;
    if (starts_with(p, "/apex/"))            return 1;
    if (starts_with(p, "/data/"))            return 1;
    if (starts_with(p, "/sdcard/"))          return 1;
    if (starts_with(p, "/storage/"))         return 1;
    /* chính path spoof — không spoof đệ quy */
    if (s_cmp(p, SPOOF_PATH) == 0)           return 1;
    return 0;
}

/* Bug #3 fix: chấp nhận cả absolute và relative "build.prop" */
static int should_spoof_path(const char *p) {
    if (!ends_with_build_prop(p)) return 0;
    if (path_excluded(p))         return 0;
    return 1;
}

/* Bug #5 fix: whitelist camera bằng get_task_comm, không dùng comm offset thô */
static int is_camera_whitelisted(void) {
    if (!p_get_task_comm) return 0;
    char comm[16] = {0};
    p_get_task_comm(comm, sizeof(comm), current);
    comm[15] = '\0';

    static const char *wl[] = {
        "camera", "cameraserver", "media.camera",
        "qti.camera", "vtcamera",
        "vendor.qti.camera", "vendor.xiaomi.hardware.camera",
        "android.hardware.camera",
    };
    for (size_t i = 0; i < sizeof(wl)/sizeof(wl[0]); i++) {
        size_t l = s_len(wl[i]);
        if (s_ncmp(comm, wl[i], l) == 0 && comm[l] == '\0') return 1;
    }
    return 0;
}

/* ==========================================================================
 * SECTION 5: FILE SPOOF HOOKS
 * ========================================================================== */

static void spoof_common(void *user_path_ptr) {
    if (!g_spoof_enabled) return;
    if (!p_ctu || !p_cfu || !user_path_ptr) return;

    char path[96];
    if (p_cfu(path, user_path_ptr, sizeof(path) - 1) != 0) return;
    path[sizeof(path) - 1] = '\0';

    if (!should_spoof_path(path)) return;
    if (is_camera_whitelisted())   return;   /* camera thấy identity thật */

    size_t path_len = s_len(path);
    if (path_len < SPOOF_PATH_LEN) return;   /* An toàn: không ghi đè nếu buffer user nhỏ hơn 18 byte */

    if (p_ctu(user_path_ptr, SPOOF_PATH, SPOOF_PATH_LEN + 1) == 0)
        g_spoof_hits++;
}

/* Bug #1 fix: CHỈ hook openat, KHÔNG hook newfstatat */
static void before_openat(hook_fargs4_t *args, void *udata) {
    (void)udata;
    spoof_common((void *)args->arg1);
}

/* Bug #2 fix: thêm openat2 cho Android 12+ */
static void before_openat2(hook_fargs4_t *args, void *udata) {
    (void)udata;
    spoof_common((void *)args->arg1);
}

/* Che /proc/self/fd/N leak */
static void after_readlinkat(hook_fargs4_t *args, void *udata) {
    (void)udata;
    if (!p_ctu || !p_cfu) return;

    long ret = (long)args->ret;
    if (ret <= 0 || ret > 200) return;

    void *user_path = (void *)args->arg1;
    void *user_buf  = (void *)args->arg2;
    size_t bufsiz   = (size_t)args->arg3;
    if (!user_path || !user_buf || bufsiz == 0) return;

    char path[64];
    if (p_cfu(path, user_path, sizeof(path) - 1) != 0) return;
    path[sizeof(path) - 1] = '\0';
    if (!is_proc_fd_path(path)) return;

    char result[256];
    if ((size_t)ret > sizeof(result)) ret = sizeof(result);
    if (p_cfu(result, user_buf, (unsigned long)ret) != 0) return;
    result[ret] = '\0';

    if (s_cmp(result, SPOOF_PATH) != 0) return;

    size_t cl = FAKE_PATH_LEN;
    if (cl > bufsiz) cl = bufsiz;
    if (p_ctu(user_buf, FAKE_PATH, cl) == 0)
        args->ret = (uint64_t)cl;
}

/* ==========================================================================
 * SECTION 6: SCHEDULER HOOK (giữ nguyên từ bản gốc)
 * ========================================================================== */

static void after_select_task_rq(hook_fargs4_t *args, void *udata) {
    (void)udata;
    void *task = (void *)args->arg0;
    if (!task || g_comm_offset <= 0) return;

    int target_cpu = (int)args->ret;
    if (target_cpu < 0 || target_cpu > 7) return;

    const char *raw = (const char *)task + g_comm_offset;
    char comm[16];
    for (int i = 0; i < 15; i++) {
        comm[i] = raw[i];
        if (raw[i] == '\0') break;
    }
    comm[15] = '\0';
    if (comm[0] == '\0') return;

    /* Dynamic rules */
    for (int i = 0; i < MAX_FORK_RULES; i++) {
        if (!g_fork_rules[i].enabled || !g_fork_rules[i].comm[0]) continue;
        /* substring — giữ nguyên behavior gốc cho rule động */
        const char *h = comm, *n = g_fork_rules[i].comm;
        int match = 0;
        while (*h) {
            const char *hh = h, *nn = n;
            while (*hh && *nn && *hh == *nn) { hh++; nn++; }
            if (!*nn) { match = 1; break; }
            h++;
        }
        if (match) {
            if (g_fork_rules[i].action == 1)      args->ret = target_cpu % 3;
            else if (g_fork_rules[i].action == 2) args->ret = 7;
            else if (g_fork_rules[i].action == 3) args->ret = 4 + (target_cpu % 3);
            return;
        }
    }
}

/* ==========================================================================
 * SECTION 7: PRCTL BRIDGE
 * ========================================================================== */

void before_prctl_hook(hook_fargs5_t *args, void *udata) {
    (void)udata;
    int option = (int)syscall_argn(args, 0);
    if (option != HEO_MAGIC_PRCTL) return;

    args->skip_origin = 1;

    unsigned long cmd = (unsigned long)syscall_argn(args, 1);
    unsigned long task_now = (unsigned long)current;

    switch (cmd) {
    case HEO_CMD_GET_CHALLENGE: {
        current_nonce = current_nonce * 6364136223846793005ULL
                      + 1442695040888963407ULL + task_now;
        uint32_t n = (uint32_t)(current_nonce & 0x7FFFFFFFU);
        if (n == 0) n = 0x1337BEEF;
        args->ret = (uint64_t)n;
        break;
    }
    case HEO_CMD_VERIFY_AUTH: {
        uint64_t tok = (uint64_t)syscall_argn(args, 2);
        uint32_t n = (uint32_t)(current_nonce & 0x7FFFFFFFU);
        if (n == 0) n = 0x1337BEEF;
        uint64_t exp = ((uint64_t)n) ^ HEO_SECRET_SALT;
        if (tok == exp) { authorized_task_ptr = task_now; args->ret = 0x1337; }
        else            { args->ret = (uint64_t)-1; }
        break;
    }
    case HEO_CMD_STATUS:
        args->ret = (authorized_task_ptr && authorized_task_ptr == task_now) ? 1 : 0;
        break;

    case HEO_CMD_FORCE_YAMA_OFF: {
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        int *p = (int *)kallsyms_lookup_name("ptrace_scope");
        if (p) *p = 0;
        args->ret = 0;
        break;
    }

    case HEO_CMD_KERNEL_TELEMETRY: {
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        void *ub = (void *)syscall_argn(args, 2);
        if (!ub || !p_ctu) { args->ret = (uint64_t)-1; break; }

        uint32_t active = 0;
        for (int i = 0; i < MAX_FORK_RULES; i++)
            if (g_fork_rules[i].enabled) active++;

        struct heo_kernel_telemetry t = {0};
        t.magic = 0x48454F30;
        t.version = 0x0500;
        t.uptime_jiffies = p_jiffies ? *p_jiffies : 0;
        t.cfs_latency     = p_sched_latency    ? *p_sched_latency    : 0;
        t.cfs_min_gran    = p_sched_min_gran   ? *p_sched_min_gran   : 0;
        t.cfs_wakeup_gran = p_sched_wakeup_gran? *p_sched_wakeup_gran: 0;
        t.active_rules_count = active;
        t.spoof_enabled = g_spoof_enabled;
        t.spoof_hits = g_spoof_hits;
        args->ret = p_ctu(ub, &t, sizeof(t)) == 0 ? 0 : (uint64_t)-14;
        break;
    }

    case HEO_CMD_SET_FORK_RULE: {
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        void *ub = (void *)syscall_argn(args, 2);
        if (!ub || !p_cfu) { args->ret = (uint64_t)-1; break; }
        struct heo_fork_rule r;
        if (p_cfu(&r, ub, sizeof(r)) != 0) { args->ret = (uint64_t)-14; break; }
        r.comm[15] = '\0';
        int slot = -1;
        for (int i = 0; i < MAX_FORK_RULES; i++)
            if (g_fork_rules[i].enabled && s_cmp(g_fork_rules[i].comm, r.comm) == 0)
                { slot = i; break; }
        if (slot < 0)
            for (int i = 0; i < MAX_FORK_RULES; i++)
                if (!g_fork_rules[i].enabled) { slot = i; break; }
        if (slot < 0) { args->ret = (uint64_t)-28; break; }
        kpm_memcpy(&g_fork_rules[slot], &r, sizeof(r));
        g_fork_rules[slot].enabled = 1;
        args->ret = 0;
        break;
    }

    case HEO_CMD_GET_FORK_RULES: {
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        void *ub = (void *)syscall_argn(args, 2);
        if (!ub || !p_ctu) { args->ret = (uint64_t)-1; break; }
        args->ret = p_ctu(ub, g_fork_rules, sizeof(g_fork_rules)) == 0
                    ? 0 : (uint64_t)-14;
        break;
    }

    case HEO_CMD_CLEAR_FORK_RULES:
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        kpm_memset(g_fork_rules, 0, sizeof(g_fork_rules));
        args->ret = 0;
        break;

    case HEO_CMD_ELEVATE_CREDS: {
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        if (!p_commit_creds || !p_prepare_kernel_cred) { args->ret = (uint64_t)-38; break; }
        void *kc = p_prepare_kernel_cred(0);
        if (!kc) { args->ret = (uint64_t)-12; break; }   /* FIX: check NULL */
        args->ret = (uint64_t)p_commit_creds(kc);
        break;
    }

    case HEO_CMD_TASK_INSPECT: {
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        int pid = (int)syscall_argn(args, 2);
        void *ub = (void *)syscall_argn(args, 3);
        if (!ub || !p_ctu || !p_find_task_by_vpid || !p_get_task_comm) {
            args->ret = (uint64_t)-22; break;
        }
        void *t = p_find_task_by_vpid(pid);
        struct heo_task_inspect_info info = {0};
        info.pid = pid;
        if (t) {
            info.exists = 1;
            info.task_ptr = (uint64_t)t;
            p_get_task_comm(info.comm, sizeof(info.comm), t);
            info.comm[15] = '\0';
        }
        args->ret = p_ctu(ub, &info, sizeof(info)) == 0
                    ? (info.exists ? 0 : (uint64_t)-3) : (uint64_t)-14;
        break;
    }

    case HEO_CMD_KREAD: {
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        uint64_t ka = (uint64_t)syscall_argn(args, 2);
        void *ub   = (void *)syscall_argn(args, 3);
        unsigned long len = (unsigned long)syscall_argn(args, 4);
        if (!ub || !p_ctu || len == 0 || len > 4096) {
            args->ret = (uint64_t)-22; break;
        }
        if (!p_knofault) { args->ret = (uint64_t)-38; break; }  /* không có nofault → từ chối */

        /* SAFE: copy_from_kernel_nofault không panic nếu addr invalid; static buffer chống tràn stack */
        static char s_kread_buf[1024];
        if (len > sizeof(s_kread_buf)) len = sizeof(s_kread_buf);
        if (p_knofault(s_kread_buf, (const void *)ka, len) != 0) {
            args->ret = (uint64_t)-14;
            break;
        }
        args->ret = p_ctu(ub, s_kread_buf, len) == 0 ? 0 : (uint64_t)-14;
        break;
    }

    case HEO_CMD_KWRITE: {
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        uint64_t ka = (uint64_t)syscall_argn(args, 2);
        const void *ub = (const void *)syscall_argn(args, 3);
        unsigned long len = (unsigned long)syscall_argn(args, 4);
        if (!ub || !p_cfu || len == 0 || len > 4096) {
            args->ret = (uint64_t)-22; break;
        }
        static char s_kwrite_buf[1024];
        if (len > sizeof(s_kwrite_buf)) len = sizeof(s_kwrite_buf);
        if (p_cfu(s_kwrite_buf, ub, len) != 0) { args->ret = (uint64_t)-14; break; }
        if (p_knofault && p_knofault(s_kwrite_buf, (const void *)ka, 1) != 0) {
            args->ret = (uint64_t)-14;   /* addr không đọc được → từ chối ghi */
            break;
        }
        kpm_memcpy((void *)ka, s_kwrite_buf, len);
        args->ret = 0;
        break;
    }

    case HEO_CMD_RESOLVE_SYMBOL: {
        if (authorized_task_ptr != task_now) { args->ret = 0; break; }
        const void *un = (const void *)syscall_argn(args, 2);
        if (!un || !p_cfu) { args->ret = 0; break; }
        char name[64] = {0};
        if (p_cfu(name, un, 63) != 0) { args->ret = 0; break; }
        name[63] = '\0';
        uint64_t sym_addr = (uint64_t)kallsyms_lookup_name(name);
        args->ret = sym_addr;
        if (p_ctu) p_ctu((void *)un, &sym_addr, sizeof(sym_addr));
        break;
    }

    case HEO_CMD_SET_TASK_AFFINITY: {
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        int pid = (int)syscall_argn(args, 2);
        unsigned long mask = (unsigned long)syscall_argn(args, 3);
        if (!p_find_task_by_vpid || !p_set_cpus_allowed_ptr) {
            args->ret = (uint64_t)-38; break;
        }
        void *t = p_find_task_by_vpid(pid);
        if (!t) { args->ret = (uint64_t)-3; break; }
        /* mask phải hợp lệ: không 0, không vượt 8 CPU */
        if ((mask & 0xFF) == 0) { args->ret = (uint64_t)-22; break; }
        args->ret = (uint64_t)p_set_cpus_allowed_ptr(t, &mask);
        break;
    }

    case HEO_CMD_SPOOF_ENABLE:
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        g_spoof_enabled = 1;
        args->ret = 0;
        break;

    case HEO_CMD_SPOOF_DISABLE:
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        g_spoof_enabled = 0;
        args->ret = 0;
        break;

    case HEO_CMD_SPOOF_STATUS:
        if (authorized_task_ptr != task_now) { args->ret = (uint64_t)-1; break; }
        args->ret = g_spoof_hits;
        break;

    default:
        args->ret = (uint64_t)-1;
        break;
    }
}

/* ==========================================================================
 * SECTION 8: COMM OFFSET RESOLVER (init-time, safe context)
 * ========================================================================== */

static int resolve_task_comm_offset(void) {
    if (!p_get_task_comm) return -1;
    char ref[16] = {0};
    p_get_task_comm(ref, sizeof(ref), current);
    ref[15] = '\0';
    size_t l = s_len(ref);
    if (l == 0) return -1;

    const unsigned char *base = (const unsigned char *)current;
    for (int off = 0x200; off < 0x1800; off += 4) {
        if (s_ncmp((const char *)(base + off), ref, l) == 0 && base[off + l] == '\0') {
            unsigned long cred = *(const unsigned long *)(base + off - 8);
            if ((cred >> 48) == 0xffff) {
                g_comm_offset = off;
                return off;
            }
        }
    }
    return -1;
}

/* ==========================================================================
 * SECTION 9: SYMBOL RESOLUTION (fallback + NULL check)
 * ========================================================================== */

static void resolve_symbols(void) {
    p_ctu = (void *)kallsyms_lookup_name("_copy_to_user");
    if (!p_ctu) p_ctu = (void *)kallsyms_lookup_name("raw_copy_to_user");
    if (!p_ctu) p_ctu = (void *)kallsyms_lookup_name("__arch_copy_to_user");

    p_cfu = (void *)kallsyms_lookup_name("_copy_from_user");
    if (!p_cfu) p_cfu = (void *)kallsyms_lookup_name("raw_copy_from_user");
    if (!p_cfu) p_cfu = (void *)kallsyms_lookup_name("__arch_copy_from_user");

    p_knofault = (void *)kallsyms_lookup_name("copy_from_kernel_nofault");
    if (!p_knofault) p_knofault = (void *)kallsyms_lookup_name("probe_kernel_read");

    p_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");

    p_jiffies = (unsigned long *)kallsyms_lookup_name("jiffies_64");
    if (!p_jiffies) p_jiffies = (unsigned long *)kallsyms_lookup_name("jiffies");

    p_sched_latency        = (unsigned int *)kallsyms_lookup_name("sysctl_sched_latency");
    p_sched_min_gran       = (unsigned int *)kallsyms_lookup_name("sysctl_sched_min_granularity");
    p_sched_wakeup_gran    = (unsigned int *)kallsyms_lookup_name("sysctl_sched_wakeup_granularity");
    p_sched_migration_cost = (unsigned int *)kallsyms_lookup_name("sysctl_sched_migration_cost");

    p_find_task_by_vpid     = (void *)kallsyms_lookup_name("find_task_by_vpid");
    p_set_cpus_allowed_ptr  = (void *)kallsyms_lookup_name("set_cpus_allowed_ptr");
    p_commit_creds          = (void *)kallsyms_lookup_name("commit_creds");
    p_prepare_kernel_cred   = (void *)kallsyms_lookup_name("prepare_kernel_cred");
    p_select_task_rq        = (void *)kallsyms_lookup_name("select_task_rq");
}

/* ==========================================================================
 * SECTION 10: INIT / EXIT
 * ========================================================================== */

static long init(const char *args, const char *event, void *reserved) {
    (void)args; (void)event; (void)reserved;

    pr_info("[HEO-KPM] ===== HEO v5.0 Merged Hardened =====\n");

    resolve_symbols();

    if (!p_ctu || !p_cfu) {
        pr_err("[HEO-KPM] copy_to/from_user unresolved — abort\n");
        return -1;
    }
    if (!p_knofault)
        pr_warn("[HEO-KPM] nofault missing — KREAD disabled\n");

    /* CFS tuning */
    if (p_sched_latency) {
        orig_sched_latency = *p_sched_latency;
        *p_sched_latency = 4000000U;
    }
    if (p_sched_min_gran) {
        orig_sched_min_gran = *p_sched_min_gran;
        *p_sched_min_gran = 750000U;
    }
    if (p_sched_wakeup_gran) {
        orig_sched_wakeup_gran = *p_sched_wakeup_gran;
        *p_sched_wakeup_gran = 1000000U;
    }
    if (p_sched_migration_cost) {
        orig_sched_migration_cost = *p_sched_migration_cost;
        *p_sched_migration_cost = 500000U;
    }

    resolve_task_comm_offset();

    /* Scheduler hook (optional — bỏ nếu p_select_task_rq NULL) */
    if (p_select_task_rq && g_comm_offset > 0) {
        hook_wrap4(p_select_task_rq, 0, after_select_task_rq, 0);
    }

    /* Spoofer hooks — CHỈ 3, KHÔNG newfstatat */
    inline_hook_syscalln(__NR_openat,     4, before_openat,  NULL, NULL);
    inline_hook_syscalln(__NR_openat2,    4, before_openat2, NULL, NULL);
    inline_hook_syscalln(__NR_readlinkat, 4, NULL, after_readlinkat, NULL);

    /* prctl bridge */
    hook_err_t e = inline_hook_syscalln(__NR_prctl, 5, before_prctl_hook, NULL, NULL);
    if (e) {
        pr_err("[HEO-KPM] prctl hook failed: %d\n", e);
        return -1;
    }

    kpm_memset(g_fork_rules, 0, sizeof(g_fork_rules));
    pr_info("[HEO-KPM] ONLINE — spoof=1, sched=%d, kread=%d\n",
            (p_select_task_rq && g_comm_offset > 0), !!p_knofault);
    return 0;
}

static long exit_fn(void *reserved) {
    (void)reserved;
    pr_info("[HEO-KPM] unloading...\n");

    inline_unhook_syscalln(__NR_prctl,     before_prctl_hook, NULL);
    inline_unhook_syscalln(__NR_readlinkat, NULL, after_readlinkat);
    inline_unhook_syscalln(__NR_openat2,   before_openat2, NULL);
    inline_unhook_syscalln(__NR_openat,    before_openat,  NULL);

    if (p_select_task_rq && g_comm_offset > 0)
        hook_unwrap(p_select_task_rq, 0, after_select_task_rq);

    if (p_sched_latency && orig_sched_latency)
        *p_sched_latency = orig_sched_latency;
    if (p_sched_min_gran && orig_sched_min_gran)
        *p_sched_min_gran = orig_sched_min_gran;
    if (p_sched_wakeup_gran && orig_sched_wakeup_gran)
        *p_sched_wakeup_gran = orig_sched_wakeup_gran;
    if (p_sched_migration_cost && orig_sched_migration_cost)
        *p_sched_migration_cost = orig_sched_migration_cost;

    authorized_task_ptr = 0;
    pr_info("[HEO-KPM] bye.\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit_fn);
