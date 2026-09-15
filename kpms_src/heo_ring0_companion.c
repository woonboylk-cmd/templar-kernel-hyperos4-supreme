/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: HEO Ring 0 Sovereign Companion v6.0.0 — Hardened Full Edition
 * Target: Xiaomi 12S (mayfly) - Snapdragon 8+ Gen 1 (SM8475) - Linux Kernel 5.10.x
 * Architecture: KernelPatch (Ring 0 EL1)
 *
 * Changelog so với v5.4.0:
 *  [SECURITY]  Auth per-tgid — không còn global (fix regression nghiêm trọng)
 *  [SAFETY]    Bỏ fallback deref thẳng khi copy_from_kernel_nofault NULL
 *  [SAFETY]    VA check mở rộng 47-bit (hỗ trợ cả 39-bit và 48-bit VA)
 *  [SAFETY]    KREAD/KWRITE chunked — không còn static buffer race
 *  [FEATURE]   KALLSYMS_LEAK walk toàn bộ bảng kallsyms thực sự
 *  [CORRECT]   PREAD dùng memremap (WB) thay ioremap_cache
 *  [CORRECT]   V2P thêm isb sau AT instruction
 *
 * Capabilities:
 *  1. Auth syscall bridge qua sys_prctl (0x48454F 'HEO')
 *  2. Zero-Lock Task Steering trên select_task_rq
 *  3. CFS latency tightening
 *  4. Ring 0 introspection (telemetry, KREAD/KWRITE, symbol resolve)
 *  5. Credential elevation
 *  6. Task inspect
 *  7. Hardware CPU affinity steering
 *  8. 6 Superpowers: KREAD_CHAIN, KALLSYMS_LEAK, LIST_WALK, V2P, PREAD, STRUCT_READ
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <hook.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("heo-ring0-companion");
KPM_VERSION("6.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("HEO Ring 0 Sovereign Companion v6.0.0 — Per-tgid auth, chunked IO, true kallsyms walk");

/* ==========================================================================
 * SECTION 0: SAFE MEMORY HELPERS
 * ========================================================================== */

static __always_inline void *kpm_memset(void *dst, int c, unsigned long n) {
    unsigned char *p = (unsigned char *)dst;
    while (n--) *p++ = (unsigned char)c;
    return dst;
}

static __always_inline void *kpm_memcpy(void *dst, const void *src, unsigned long n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

static __always_inline int kpm_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

/* ==========================================================================
 * SECTION 1: COMMAND CONSTANTS
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

/* Superpowers */
#define HEO_CMD_KREAD_CHAIN       0x10
#define HEO_CMD_KALLSYMS_LEAK     0x11
#define HEO_CMD_LIST_WALK         0x12
#define HEO_CMD_V2P               0x13
#define HEO_CMD_PREAD             0x14
#define HEO_CMD_STRUCT_READ       0x15

#define HEO_SECRET_SALT          0xA55A1337BEEFCAFEULL
#define MAX_FORK_RULES           16

/* ==========================================================================
 * SECTION 2: STRUCTS
 * ========================================================================== */

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
};

struct heo_task_inspect_info {
    uint32_t pid;
    uint32_t exists;
    char     comm[16];
    uint64_t task_ptr;
};

/* Superpower: KREAD_CHAIN */
struct __attribute__((packed)) heo_chain_req {
    uint64_t base_ptr;
    uint32_t num_hops;
    uint32_t read_len;
    uint64_t offsets[8];
};

struct __attribute__((packed)) heo_chain_resp {
    uint64_t final_ptr;
    uint32_t bytes_read;
    uint8_t  data[1024];
};

/* Superpower: KALLSYMS_LEAK (rewrite hoàn chỉnh) */
struct __attribute__((packed)) heo_kallsyms_req {
    char     filter[32];
    uint32_t start_idx;
    uint32_t max_entries;
};

struct __attribute__((packed)) heo_sym_entry {
    char     name[56];
    uint64_t addr;
};

struct __attribute__((packed)) heo_kallsyms_resp {
    uint32_t count;
    uint32_t next_idx;
    uint32_t total_syms;
    uint32_t scanned;
    struct heo_sym_entry entries[16];
};

/* Superpower: LIST_WALK */
struct __attribute__((packed)) heo_list_walk_req {
    uint64_t head_ptr;
    uint32_t offset_in_struct;
    uint32_t max_count;
};

struct __attribute__((packed)) heo_list_walk_resp {
    uint32_t count;
    uint64_t entries[32];
};

/* Shared response buffer — fit all */
static union {
    struct heo_chain_resp      chain;      /* 1036 B */
    struct heo_kallsyms_resp   kallsyms;   /* 1040 B */
    struct heo_list_walk_resp  list_walk;  /*  260 B */
    uint8_t raw[1100];
} u_resp_buf;

/* ==========================================================================
 * SECTION 3: MODULE STATE
 * ========================================================================== */

/* Auth: up to 8 concurrent processes */
static int           g_authorized_tgids[8] = {0};
static unsigned long g_authorized_task_ptrs[8] = {0};
static int           g_auth_idx = 0;

static uint64_t current_nonce = 0x1337CAFEBEEFULL;
static struct heo_fork_rule g_fork_rules[MAX_FORK_RULES];
static int g_comm_offset = -1;

/* Symbol pointers — copy */
static unsigned long (*p_copy_to_user)(void *, const void *, unsigned long) = 0;
static unsigned long (*p_copy_from_user)(void *, const void *, unsigned long) = 0;
static long (*p_knofault)(void *, const void *, size_t) = 0;

/* Symbol pointers — task */
static char *(*p_get_task_comm)(char *, unsigned long, void *) = 0;
static void *(*p_find_task_by_vpid)(int) = 0;
static int   (*p_set_cpus_allowed_ptr)(void *, const void *) = 0;
static int   (*p_commit_creds)(void *) = 0;
static void *(*p_prepare_kernel_cred)(void *) = 0;
static int   (*p_task_tgid_vnr)(void *) = 0;

/* Symbol pointers — mapping */
static void *(*p_ioremap_cache)(unsigned long, size_t) = 0;
static void  (*p_iounmap)(void *) = 0;
static void *(*p_memremap)(unsigned long, size_t, unsigned long) = 0;
static void  (*p_memunmap)(void *) = 0;

/* Symbol pointers — misc */
static void *p_select_task_rq = 0;
static unsigned long *p_jiffies = 0;

/* CFS tunables */
static unsigned int *p_sched_latency = 0;
static unsigned int *p_sched_min_gran = 0;
static unsigned int *p_sched_wakeup_gran = 0;
static unsigned int *p_sched_migration_cost = 0;
static unsigned int orig_sched_latency = 0;
static unsigned int orig_sched_min_gran = 0;
static unsigned int orig_sched_wakeup_gran = 0;
static unsigned int orig_sched_migration_cost = 0;

/* Kallsyms table pointers */
static void          *p_kallsyms_offsets = 0;
static void          *p_kallsyms_addresses = 0;
static unsigned long *p_kallsyms_relative_base = 0;
static unsigned long  g_kallsyms_relative_base_val = 0;
static void          *p_kallsyms_num_syms = 0;
static void          *p_kallsyms_names = 0;
static void          *p_kallsyms_markers = 0;
static void          *p_kallsyms_token_table = 0;
static void          *p_kallsyms_token_index = 0;

/* Telemetry counters */
static volatile unsigned long stat_tasks_steered = 0;
static volatile unsigned long stat_bloat_demotes = 0;
static volatile unsigned long stat_ui_boosts = 0;
static volatile unsigned long stat_ai_steers = 0;

/* ==========================================================================
 * SECTION 4: LOW-LEVEL HELPERS
 * ========================================================================== */

static inline size_t k_strlen(const char *s) {
    size_t len = 0;
    while (s && s[len]) len++;
    return len;
}

static inline int str_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    const char *h = haystack;
    while (*h) {
        const char *h_sub = h;
        const char *n_sub = needle;
        while (*h_sub && *n_sub && (*h_sub == *n_sub)) { h_sub++; n_sub++; }
        if (!*n_sub) return 1;
        h++;
    }
    return 0;
}

/* 47-bit VA ceiling — an toàn cho cả 39-bit và 48-bit config */
static inline int is_valid_user_addr(const void *addr, unsigned long n) {
    unsigned long a = (unsigned long)addr;
    if (a == 0) return 0;
    if (a >= 0x0001000000000000UL) return 0;
    if (n > 0 && (a + n) < a) return 0;
    return 1;
}

static inline unsigned long safe_copy_to_user(void *to, const void *from, unsigned long n) {
    if (!is_valid_user_addr(to, n)) return n;
    if (p_copy_to_user) return p_copy_to_user(to, from, n);
    return compat_copy_to_user(to, from, (int)n);
}

static inline unsigned long safe_copy_from_user(void *to, const void *from, unsigned long n) {
    if (!is_valid_user_addr(from, n)) return (unsigned long)-14;
    if (p_copy_from_user) return p_copy_from_user(to, from, n);
    if (compat_strncpy_from_user((char *)to, (const char *)from, (long)n) >= 0) return 0;
    return (unsigned long)-14;
}

/* Per-tgid auth check (multi-process) */
static inline int is_authorized_task(void) {
    if (p_task_tgid_vnr) {
        int tgid = p_task_tgid_vnr(current);
        if (tgid != 0) {
            for (int i = 0; i < 8; i++) {
                if (g_authorized_tgids[i] == tgid) return 1;
            }
        }
    }
    unsigned long curr_ptr = (unsigned long)current;
    for (int i = 0; i < 8; i++) {
        if (g_authorized_task_ptrs[i] == curr_ptr && curr_ptr != 0) return 1;
    }
    return 0;
}

/* Chunked kread: kernel → user, không dùng static buffer */
static long kread_safe(unsigned long kaddr, void *user_buf, unsigned long len) {
    if (!p_knofault) return -38;   /* ENOSYS */
    if (!is_valid_user_addr(user_buf, len)) return -14;

    char chunk[128];
    unsigned long done = 0;
    while (done < len) {
        unsigned long n = len - done;
        if (n > sizeof(chunk)) n = sizeof(chunk);
        if (p_knofault(chunk, (const void *)(kaddr + done), n) != 0) return -14;
        if (safe_copy_to_user((char *)user_buf + done, chunk, n) != 0) return -14;
        done += n;
    }
    return 0;
}

/* Chunked kwrite: user → kernel, pre-check read */
static long kwrite_safe(unsigned long kaddr, const void *user_buf, unsigned long len) {
    if (!p_knofault) return -38;
    if (!is_valid_user_addr(user_buf, len)) return -14;

    char chunk[128];
    unsigned long done = 0;
    while (done < len) {
        unsigned long n = len - done;
        if (n > sizeof(chunk)) n = sizeof(chunk);
        if (safe_copy_from_user(chunk, (const char *)user_buf + done, n) != 0) return -14;
        /* Pre-check: vùng đích có đọc được không */
        char probe;
        if (p_knofault(&probe, (const void *)(kaddr + done), 1) != 0) return -14;
        kpm_memcpy((void *)(kaddr + done), chunk, n);
        done += n;
    }
    return 0;
}

/* ==========================================================================
 * SECTION 5: KALLSYMS DECODER
 * ========================================================================== */

static int kr_u8(const void *addr, unsigned char *out) {
    return (p_knofault && p_knofault(out, addr, 1) == 0) ? 0 : -1;
}
static int kr_u16(const void *addr, unsigned short *out) {
    return (p_knofault && p_knofault(out, addr, 2) == 0) ? 0 : -1;
}
static int kr_u32(const void *addr, unsigned int *out) {
    return (p_knofault && p_knofault(out, addr, 4) == 0) ? 0 : -1;
}

/* Tìm byte-offset của symbol N trong kallsyms_names */
static int kallsyms_find_offset(unsigned int sym_idx, unsigned int *out_pos) {
    if (!p_kallsyms_names || !p_kallsyms_markers) return -1;
    if (sym_idx == 0) { *out_pos = 0; return 0; }

    unsigned int marker_idx = sym_idx / 256;
    unsigned int marker = 0;
    if (kr_u32((char *)p_kallsyms_markers + marker_idx * 4, &marker) != 0) return -1;

    unsigned int pos = marker;
    unsigned int start = marker_idx * 256;
    const char *names = (const char *)p_kallsyms_names;

    for (unsigned int i = start; i < sym_idx; i++) {
        unsigned char b;
        if (kr_u8(names + pos, &b) != 0) return -1;
        unsigned int len;
        if (b & 0x80) {
            unsigned char b2;
            if (kr_u8(names + pos + 1, &b2) != 0) return -1;
            len = (b & 0x7F) | ((unsigned int)b2 << 7);
            pos += 2 + len;
        } else {
            len = b;
            pos += 1 + len;
        }
    }
    *out_pos = pos;
    return 0;
}

/* Decode name tại offset */
static int kallsyms_decode_name(unsigned int offset, char *out, int max_out) {
    if (!p_kallsyms_names || !p_kallsyms_token_table || !p_kallsyms_token_index) return -1;

    unsigned char b;
    if (kr_u8((char *)p_kallsyms_names + offset, &b) != 0) return -1;

    unsigned int len;
    unsigned int pos;
    if (b & 0x80) {
        unsigned char b2;
        if (kr_u8((char *)p_kallsyms_names + offset + 1, &b2) != 0) return -1;
        len = (b & 0x7F) | ((unsigned int)b2 << 7);
        pos = offset + 2;
    } else {
        len = b;
        pos = offset + 1;
    }

    int op = 0;
    for (unsigned int i = 0; i < len && op < max_out - 1; i++) {
        unsigned char tok;
        if (kr_u8((char *)p_kallsyms_names + pos + i, &tok) != 0) return -1;

        unsigned short idx = 0;
        if (kr_u16((char *)p_kallsyms_token_index + tok * 2, &idx) != 0) return -1;

        for (int j = 0; op < max_out - 1; j++) {
            unsigned char c;
            if (kr_u8((char *)p_kallsyms_token_table + idx + j, &c) != 0) return -1;
            if (c == 0) break;
            out[op++] = (char)c;
        }
    }
    out[op] = 0;
    return op;
}

/* Đọc address của symbol N */
static int kallsyms_get_addr(unsigned int n, unsigned long *out) {
    if (p_kallsyms_addresses) {
        unsigned long a = 0;
        if (p_knofault(&a, (char *)p_kallsyms_addresses + n * 8, 8) != 0) return -1;
        *out = a;
        return 0;
    }
    if (p_kallsyms_offsets && g_kallsyms_relative_base_val) {
        unsigned int raw = 0;
        if (kr_u32((char *)p_kallsyms_offsets + n * 4, &raw) != 0) return -1;
        int off = (int)raw;
        if (off >= 0)
            *out = g_kallsyms_relative_base_val + (unsigned long)off;
        else
            *out = g_kallsyms_relative_base_val - 1 - (unsigned long)off;
        return 0;
    }
    return -1;
}

static unsigned int kallsyms_total(void) {
    unsigned int n = 0;
    if (p_kallsyms_num_syms && kr_u32(p_kallsyms_num_syms, &n) == 0) return n;
    return 0;
}

/* ==========================================================================
 * SECTION 6: COMM OFFSET RESOLVER
 * ========================================================================== */

static int resolve_task_comm_offset(void) {
    if (!p_get_task_comm) {
        pr_warn("[HEO-KPM] __get_task_comm not resolved\n");
        return -1;
    }

    char ref_name[16] = {0};
    p_get_task_comm(ref_name, sizeof(ref_name), current);
    ref_name[15] = '\0';

    size_t len = k_strlen(ref_name);
    if (len == 0) return -1;

    const unsigned char *base = (const unsigned char *)current;
    int candidate = -1;
    int match_count = 0;

    for (int offset = 0x200; offset < 0x1800; offset += 4) {
        int match = 1;
        for (size_t j = 0; j < len; j++) {
            if (base[offset + j] != (unsigned char)ref_name[j]) { match = 0; break; }
        }
        if (match && base[offset + len] == '\0') {
            candidate = offset;
            match_count++;
        }
    }

    if (candidate > 0) {
        g_comm_offset = candidate;
        pr_info("[HEO-KPM] comm offset: 0x%x (matches=%d)\n", candidate, match_count);
        return candidate;
    }
    return -1;
}

/* ==========================================================================
 * SECTION 7: SCHEDULER HOOK
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
        if (g_fork_rules[i].enabled && g_fork_rules[i].comm[0]) {
            if (str_contains(comm, g_fork_rules[i].comm)) {
                if (g_fork_rules[i].action == 1)      { args->ret = target_cpu % 3; stat_bloat_demotes++; }
                else if (g_fork_rules[i].action == 2) { args->ret = 7; stat_ui_boosts++; }
                else if (g_fork_rules[i].action == 3) { args->ret = 4 + (target_cpu % 3); stat_ai_steers++; }
                stat_tasks_steered++;
                return;
            }
        }
    }

    /* Built-in bloatware demotion */
    if (str_contains(comm, "facebook") || str_contains(comm, "katana") ||
        str_contains(comm, "orca")     || str_contains(comm, "instagram") ||
        str_contains(comm, "tiktok")   || str_contains(comm, "zhiliao") ||
        str_contains(comm, "miwallpap")|| str_contains(comm, "earthSuper")) {
        if (target_cpu >= 3) {
            args->ret = target_cpu % 3;
            stat_bloat_demotes++; stat_tasks_steered++;
        }
        return;
    }

    /* AI engines → A710 */
    if (str_contains(comm, "llama") || str_contains(comm, "qwen") ||
        str_contains(comm, "executor")) {
        if (target_cpu < 4 || target_cpu == 7) {
            args->ret = 4 + (target_cpu % 3);
            stat_ai_steers++; stat_tasks_steered++;
        }
        return;
    }

    /* UI → X2 */
    if (str_contains(comm, "surfacefl")  || str_contains(comm, "RenderThrea") ||
        str_contains(comm, "composer-s")) {
        if (target_cpu < 4) {
            args->ret = 7;
            stat_ui_boosts++; stat_tasks_steered++;
        }
        return;
    }
}

/* ==========================================================================
 * SECTION 8: PRCTL BRIDGE
 * ========================================================================== */

static void before_prctl_hook(hook_fargs5_t *args, void *udata) {
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
        uint32_t nonce32 = (uint32_t)(current_nonce & 0x7FFFFFFFU);
        if (nonce32 == 0) nonce32 = 0x1337BEEF;
        args->ret = (uint64_t)nonce32;
        break;
    }

    case HEO_CMD_VERIFY_AUTH: {
        uint64_t client_token = (uint64_t)syscall_argn(args, 2);
        uint32_t nonce32 = (uint32_t)(current_nonce & 0x7FFFFFFFU);
        if (nonce32 == 0) nonce32 = 0x1337BEEF;
        uint64_t expected_token = ((uint64_t)nonce32) ^ HEO_SECRET_SALT;

        if (client_token == expected_token) {
            int slot = g_auth_idx % 8;
            if (p_task_tgid_vnr) {
                int tgid = p_task_tgid_vnr(current);
                g_authorized_tgids[slot] = tgid;
                g_authorized_task_ptrs[slot] = task_now;
                pr_info("[HEO-KPM] AUTH OK tgid=%d at slot %d\n", tgid, slot);
            } else {
                g_authorized_tgids[slot] = 0;
                g_authorized_task_ptrs[slot] = task_now;
                pr_info("[HEO-KPM] AUTH OK ptr=0x%lx at slot %d\n", task_now, slot);
            }
            g_auth_idx++;
            args->ret = 0x1337;
        } else {
            args->ret = (uint64_t)-1;
        }
        break;
    }

    case HEO_CMD_STATUS:
        args->ret = is_authorized_task() ? 1 : 0;
        break;

    case HEO_CMD_FORCE_YAMA_OFF: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        int *p = (int *)kallsyms_lookup_name("ptrace_scope");
        if (p) *p = 0;
        args->ret = 0;
        break;
    }

    case HEO_CMD_KERNEL_TELEMETRY: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        void *ub = (void *)syscall_argn(args, 2);
        if (!ub) { args->ret = (uint64_t)-1; break; }

        uint32_t active = 0;
        for (int i = 0; i < MAX_FORK_RULES; i++)
            if (g_fork_rules[i].enabled) active++;

        struct heo_kernel_telemetry t;
        kpm_memset(&t, 0, sizeof(t));
        t.magic = 0x48454F30;
        t.version = 0x0600;
        t.uptime_jiffies = p_jiffies ? *p_jiffies : 0;
        t.cfs_latency     = p_sched_latency     ? *p_sched_latency : 0;
        t.cfs_min_gran    = p_sched_min_gran    ? *p_sched_min_gran : 0;
        t.cfs_wakeup_gran = p_sched_wakeup_gran ? *p_sched_wakeup_gran : 0;
        t.total_tasks_steered = stat_tasks_steered;
        t.bloat_demotes = stat_bloat_demotes;
        t.ui_boosts = stat_ui_boosts;
        t.ai_steers = stat_ai_steers;
        t.active_rules_count = active;
        args->ret = (safe_copy_to_user(ub, &t, sizeof(t)) == 0) ? 0 : (uint64_t)-14;
        break;
    }

    case HEO_CMD_SET_FORK_RULE: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        void *ub = (void *)syscall_argn(args, 2);
        if (!ub) { args->ret = (uint64_t)-1; break; }
        struct heo_fork_rule r;
        if (safe_copy_from_user(&r, ub, sizeof(r)) != 0) { args->ret = (uint64_t)-14; break; }
        r.comm[15] = '\0';

        int slot = -1;
        for (int i = 0; i < MAX_FORK_RULES; i++)
            if (g_fork_rules[i].enabled && kpm_strcmp(g_fork_rules[i].comm, r.comm) == 0)
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
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        void *ub = (void *)syscall_argn(args, 2);
        if (!ub) { args->ret = (uint64_t)-1; break; }
        args->ret = (safe_copy_to_user(ub, g_fork_rules, sizeof(g_fork_rules)) == 0)
                    ? 0 : (uint64_t)-14;
        break;
    }

    case HEO_CMD_CLEAR_FORK_RULES:
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        kpm_memset(g_fork_rules, 0, sizeof(g_fork_rules));
        args->ret = 0;
        break;

    case HEO_CMD_ELEVATE_CREDS: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        if (!p_commit_creds || !p_prepare_kernel_cred) { args->ret = (uint64_t)-38; break; }
        void *kc = p_prepare_kernel_cred(NULL);
        if (!kc) { args->ret = (uint64_t)-12; break; }
        args->ret = (uint64_t)p_commit_creds(kc);
        pr_info("[HEO-KPM] creds elevated\n");
        break;
    }

    case HEO_CMD_TASK_INSPECT: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        int pid = (int)syscall_argn(args, 2);
        void *ub = (void *)syscall_argn(args, 3);
        if (!ub || !p_find_task_by_vpid || !p_get_task_comm) {
            args->ret = (uint64_t)-22; break;
        }
        void *t = p_find_task_by_vpid(pid);
        struct heo_task_inspect_info info;
        kpm_memset(&info, 0, sizeof(info));
        info.pid = pid;
        if (t) {
            info.exists = 1;
            info.task_ptr = (unsigned long)t;
            p_get_task_comm(info.comm, sizeof(info.comm), t);
            info.comm[15] = '\0';
        }
        if (safe_copy_to_user(ub, &info, sizeof(info)) == 0)
            args->ret = info.exists ? 0 : (uint64_t)-3;
        else
            args->ret = (uint64_t)-14;
        break;
    }

    case HEO_CMD_KREAD: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        unsigned long kaddr = (unsigned long)syscall_argn(args, 2);
        void *ub = (void *)syscall_argn(args, 3);
        unsigned long len = (unsigned long)syscall_argn(args, 4);
        if (!ub || len == 0 || len > 65536) { args->ret = (uint64_t)-22; break; }
        args->ret = (uint64_t)kread_safe(kaddr, ub, len);
        break;
    }

    case HEO_CMD_KWRITE: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        unsigned long kaddr = (unsigned long)syscall_argn(args, 2);
        const void *ub = (const void *)syscall_argn(args, 3);
        unsigned long len = (unsigned long)syscall_argn(args, 4);
        if (!ub || len == 0 || len > 65536) { args->ret = (uint64_t)-22; break; }
        args->ret = (uint64_t)kwrite_safe(kaddr, ub, len);
        break;
    }

    case HEO_CMD_RESOLVE_SYMBOL: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        void *ub = (void *)syscall_argn(args, 2);
        if (!ub) { args->ret = 0; break; }
        char name[64];
        kpm_memset(name, 0, sizeof(name));
        if (safe_copy_from_user(name, ub, 63) != 0) { args->ret = (uint64_t)-14; break; }
        name[63] = '\0';
        unsigned long addr = (unsigned long)kallsyms_lookup_name(name);
        safe_copy_to_user(ub, &addr, sizeof(addr));
        args->ret = addr ? 0 : (uint64_t)-1;
        break;
    }

    case HEO_CMD_SET_TASK_AFFINITY: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        int pid = (int)syscall_argn(args, 2);
        unsigned long mask = (unsigned long)syscall_argn(args, 3);
        if (!p_find_task_by_vpid || !p_set_cpus_allowed_ptr) { args->ret = (uint64_t)-38; break; }
        void *t = p_find_task_by_vpid(pid);
        if (!t) { args->ret = (uint64_t)-3; break; }
        if ((mask & 0xFF) == 0) { args->ret = (uint64_t)-22; break; }
        args->ret = (uint64_t)p_set_cpus_allowed_ptr(t, (const void *)&mask);
        break;
    }

    /* ═══ 0x10: KREAD_CHAIN ═══ */
    case HEO_CMD_KREAD_CHAIN: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        if (!p_knofault) { args->ret = (uint64_t)-38; break; }

        void *user_req  = (void *)syscall_argn(args, 2);
        void *user_resp = (void *)syscall_argn(args, 3);
        if (!user_req || !user_resp) { args->ret = (uint64_t)-22; break; }

        struct heo_chain_req req;
        if (safe_copy_from_user(&req, user_req, sizeof(req)) != 0) {
            args->ret = (uint64_t)-14; break;
        }
        if (req.num_hops > 8 || req.read_len > sizeof(u_resp_buf.chain.data)) {
            args->ret = (uint64_t)-22; break;
        }

        uint64_t curr = req.base_ptr;
        int failed = 0;
        for (uint32_t h = 0; h < req.num_hops; h++) {
            uint64_t next_addr = curr + req.offsets[h];
            uint64_t deref_val = 0;
            if (p_knofault(&deref_val, (const void *)next_addr, sizeof(deref_val)) != 0) {
                failed = 1; break;
            }
            curr = deref_val;
        }
        if (failed || curr == 0) { args->ret = (uint64_t)-14; break; }

        kpm_memset(&u_resp_buf.chain, 0, sizeof(u_resp_buf.chain));
        u_resp_buf.chain.final_ptr = curr;
        if (req.read_len > 0) {
            if (p_knofault(u_resp_buf.chain.data, (const void *)curr, req.read_len) == 0)
                u_resp_buf.chain.bytes_read = req.read_len;
        }
        args->ret = (safe_copy_to_user(user_resp, &u_resp_buf.chain,
                     sizeof(u_resp_buf.chain)) == 0) ? 0 : (uint64_t)-14;
        break;
    }

    /* ═══ 0x11: KALLSYMS_LEAK — true walker ═══ */
    case HEO_CMD_KALLSYMS_LEAK: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        if (!p_knofault) { args->ret = (uint64_t)-38; break; }

        void *user_req  = (void *)syscall_argn(args, 2);
        void *user_resp = (void *)syscall_argn(args, 3);
        if (!user_req || !user_resp) { args->ret = (uint64_t)-22; break; }

        struct heo_kallsyms_req req;
        if (safe_copy_from_user(&req, user_req, sizeof(req)) != 0) {
            args->ret = (uint64_t)-14; break;
        }
        req.filter[31] = '\0';
        if (req.max_entries == 0 || req.max_entries > 16) req.max_entries = 16;

        unsigned int total = kallsyms_total();
        if (total == 0) { args->ret = (uint64_t)-38; break; }

        kpm_memset(&u_resp_buf.kallsyms, 0, sizeof(u_resp_buf.kallsyms));

        unsigned int start = req.start_idx;
        if (start >= total) {
            u_resp_buf.kallsyms.total_syms = total;
            u_resp_buf.kallsyms.next_idx = total;
            args->ret = (safe_copy_to_user(user_resp, &u_resp_buf.kallsyms,
                         sizeof(u_resp_buf.kallsyms)) == 0) ? 0 : (uint64_t)-14;
            break;
        }

        /* Giới hạn scan/lần để không block CPU */
        const unsigned int SCAN_LIMIT = 30000;
        unsigned int end = start + SCAN_LIMIT;
        if (end > total) end = total;

        int match_all = (req.filter[0] == '\0');

        unsigned int found = 0;
        unsigned int i = start;
        for (; i < end && found < req.max_entries; i++) {
            unsigned int off;
            if (kallsyms_find_offset(i, &off) != 0) break;

            char name[56];
            if (kallsyms_decode_name(off, name, sizeof(name)) < 0) continue;
            if (!match_all && !str_contains(name, req.filter)) continue;

            unsigned long addr = 0;
            if (kallsyms_get_addr(i, &addr) != 0) continue;

            struct heo_sym_entry *e = &u_resp_buf.kallsyms.entries[found];
            int ci = 0;
            while (ci < 55 && name[ci]) { e->name[ci] = name[ci]; ci++; }
            e->name[ci] = '\0';
            e->addr = addr;
            found++;
        }

        u_resp_buf.kallsyms.count      = found;
        u_resp_buf.kallsyms.next_idx   = i;
        u_resp_buf.kallsyms.total_syms = total;
        u_resp_buf.kallsyms.scanned    = (i - start);

        args->ret = (safe_copy_to_user(user_resp, &u_resp_buf.kallsyms,
                     sizeof(u_resp_buf.kallsyms)) == 0) ? 0 : (uint64_t)-14;
        break;
    }

    /* ═══ 0x12: LIST_WALK ═══ */
    case HEO_CMD_LIST_WALK: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        if (!p_knofault) { args->ret = (uint64_t)-38; break; }

        void *user_req  = (void *)syscall_argn(args, 2);
        void *user_resp = (void *)syscall_argn(args, 3);
        if (!user_req || !user_resp) { args->ret = (uint64_t)-22; break; }

        struct heo_list_walk_req req;
        if (safe_copy_from_user(&req, user_req, sizeof(req)) != 0) {
            args->ret = (uint64_t)-14; break;
        }
        if (req.max_count > 32) req.max_count = 32;

        kpm_memset(&u_resp_buf.list_walk, 0, sizeof(u_resp_buf.list_walk));
        uint64_t curr = req.head_ptr;
        uint32_t c = 0;
        while (curr && c < req.max_count) {
            uint64_t next_node = 0;
            if (p_knofault(&next_node, (const void *)curr, sizeof(next_node)) != 0) break;
            if (!next_node || next_node == req.head_ptr) break;
            u_resp_buf.list_walk.entries[c++] = next_node - req.offset_in_struct;
            curr = next_node;
        }
        u_resp_buf.list_walk.count = c;
        args->ret = (safe_copy_to_user(user_resp, &u_resp_buf.list_walk,
                     sizeof(u_resp_buf.list_walk)) == 0) ? 0 : (uint64_t)-14;
        break;
    }

    /* ═══ 0x13: V2P ═══ */
    case HEO_CMD_V2P: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        uint64_t vaddr = (uint64_t)syscall_argn(args, 2);
        void *ub = (void *)syscall_argn(args, 3);
        uint64_t par_val = 0;
        asm volatile("at s1e1r, %1\n\tisb\n\tmrs %0, par_el1"
                     : "=r"(par_val) : "r"(vaddr) : "memory");
        uint64_t paddr = 0;
        if ((par_val & 1ULL) == 0) {
            paddr = (par_val & 0x0000FFFFFFFFF000ULL) | (vaddr & 0xFFFULL);
        }
        if (ub) safe_copy_to_user(ub, &paddr, sizeof(paddr));
        args->ret = paddr ? 0 : (uint64_t)-14;
        break;
    }

    /* ═══ 0x14: PREAD ═══ */
    case HEO_CMD_PREAD: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        unsigned long paddr = (unsigned long)syscall_argn(args, 2);
        void *ub = (void *)syscall_argn(args, 3);
        unsigned long len = (unsigned long)syscall_argn(args, 4);
        if (!ub || len == 0 || len > 4096) { args->ret = (uint64_t)-22; break; }

        char chunk[128];

        if (p_memremap && p_memunmap) {
            /* MEMREMAP_WB = 1 */
            void *mapped = p_memremap(paddr, len, 1);
            if (!mapped) { args->ret = (uint64_t)-14; break; }
            long r = 0;
            unsigned long done = 0;
            while (done < len) {
                unsigned long n = len - done;
                if (n > sizeof(chunk)) n = sizeof(chunk);
                if (p_knofault) {
                    if (p_knofault(chunk, (char *)mapped + done, n) != 0) { r = -14; break; }
                } else {
                    kpm_memcpy(chunk, (char *)mapped + done, n);
                }
                if (safe_copy_to_user((char *)ub + done, chunk, n) != 0) { r = -14; break; }
                done += n;
            }
            p_memunmap(mapped);
            args->ret = (uint64_t)r;
            break;
        }

        if (p_ioremap_cache && p_iounmap) {
            void *mapped = p_ioremap_cache(paddr, len);
            if (!mapped) { args->ret = (uint64_t)-14; break; }
            long r = 0;
            unsigned long done = 0;
            while (done < len) {
                unsigned long n = len - done;
                if (n > sizeof(chunk)) n = sizeof(chunk);
                if (p_knofault) {
                    if (p_knofault(chunk, (char *)mapped + done, n) != 0) { r = -14; break; }
                } else {
                    kpm_memcpy(chunk, (char *)mapped + done, n);
                }
                if (safe_copy_to_user((char *)ub + done, chunk, n) != 0) { r = -14; break; }
                done += n;
            }
            p_iounmap(mapped);
            args->ret = (uint64_t)r;
            break;
        }

        args->ret = (uint64_t)-38;
        break;
    }

    /* ═══ 0x15: STRUCT_READ ═══ */
    case HEO_CMD_STRUCT_READ: {
        if (!is_authorized_task()) { args->ret = (uint64_t)-1; break; }
        if (!p_knofault) { args->ret = (uint64_t)-38; break; }

        uint64_t base = (uint64_t)syscall_argn(args, 2);
        uint64_t packed = (uint64_t)syscall_argn(args, 3);
        uint32_t offset = (uint32_t)(packed & 0xFFFFFFFFU);
        uint32_t len = (uint32_t)((packed >> 32) & 0xFFFFFFFFU);
        void *ub = (void *)syscall_argn(args, 4);
        if (!ub || len == 0 || len > 1024) { args->ret = (uint64_t)-22; break; }

        args->ret = (uint64_t)kread_safe(base + offset, ub, len);
        break;
    }

    default:
        args->ret = (uint64_t)-1;
        break;
    }
}

/* ==========================================================================
 * SECTION 9: INIT / EXIT
 * ========================================================================== */

static long heo_companion_init(const char *args, const char *event, void *reserved) {
    (void)args; (void)event; (void)reserved;

    pr_info("[HEO-KPM] ===== HEO Ring 0 Sovereign Companion v6.0.0 =====\n");

    /* 1. Core symbol resolution */
    p_copy_to_user = (void *)kallsyms_lookup_name("copy_to_user_nofault");
    if (!p_copy_to_user) p_copy_to_user = (void *)kallsyms_lookup_name("__arch_copy_to_user");
    if (!p_copy_to_user) p_copy_to_user = (void *)kallsyms_lookup_name("_copy_to_user");

    p_copy_from_user = (void *)kallsyms_lookup_name("copy_from_user_nofault");
    if (!p_copy_from_user) p_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if (!p_copy_from_user) p_copy_from_user = (void *)kallsyms_lookup_name("_copy_from_user");

    p_knofault = (void *)kallsyms_lookup_name("copy_from_kernel_nofault");
    if (!p_knofault) p_knofault = (void *)kallsyms_lookup_name("probe_kernel_read");

    /* 2. Task helpers */
    p_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    if (!p_get_task_comm) p_get_task_comm = (void *)kallsyms_lookup_name("get_task_comm");

    p_task_tgid_vnr = (void *)kallsyms_lookup_name("task_tgid_vnr");
    if (!p_task_tgid_vnr) p_task_tgid_vnr = (void *)kallsyms_lookup_name("__task_pid_nr_ns");

    p_find_task_by_vpid = (void *)kallsyms_lookup_name("find_task_by_vpid");
    p_set_cpus_allowed_ptr = (void *)kallsyms_lookup_name("set_cpus_allowed_ptr");
    p_commit_creds = (void *)kallsyms_lookup_name("commit_creds");
    p_prepare_kernel_cred = (void *)kallsyms_lookup_name("prepare_kernel_cred");

    /* 3. Mapping */
    p_ioremap_cache = (void *)kallsyms_lookup_name("ioremap_cache");
    p_iounmap = (void *)kallsyms_lookup_name("iounmap");
    p_memremap = (void *)kallsyms_lookup_name("memremap");
    p_memunmap = (void *)kallsyms_lookup_name("memunmap");

    /* 4. Misc */
    p_jiffies = (unsigned long *)kallsyms_lookup_name("jiffies_64");
    if (!p_jiffies) p_jiffies = (unsigned long *)kallsyms_lookup_name("jiffies");

    /* 5. CFS tunables */
    p_sched_latency = (unsigned int *)kallsyms_lookup_name("sysctl_sched_latency");
    p_sched_min_gran = (unsigned int *)kallsyms_lookup_name("sysctl_sched_min_granularity");
    p_sched_wakeup_gran = (unsigned int *)kallsyms_lookup_name("sysctl_sched_wakeup_granularity");
    p_sched_migration_cost = (unsigned int *)kallsyms_lookup_name("sysctl_sched_migration_cost");

    if (p_sched_latency)        { orig_sched_latency = *p_sched_latency;             *p_sched_latency = 4000000U; }
    if (p_sched_min_gran)       { orig_sched_min_gran = *p_sched_min_gran;           *p_sched_min_gran = 750000U; }
    if (p_sched_wakeup_gran)    { orig_sched_wakeup_gran = *p_sched_wakeup_gran;     *p_sched_wakeup_gran = 1000000U; }
    if (p_sched_migration_cost) { orig_sched_migration_cost = *p_sched_migration_cost; *p_sched_migration_cost = 500000U; }

    /* 6. Kallsyms table */
    p_kallsyms_offsets     = (void *)kallsyms_lookup_name("kallsyms_offsets");
    p_kallsyms_addresses   = (void *)kallsyms_lookup_name("kallsyms_addresses");
    p_kallsyms_relative_base = (unsigned long *)kallsyms_lookup_name("kallsyms_relative_base");
    p_kallsyms_num_syms    = (void *)kallsyms_lookup_name("kallsyms_num_syms");
    p_kallsyms_names       = (void *)kallsyms_lookup_name("kallsyms_names");
    p_kallsyms_markers     = (void *)kallsyms_lookup_name("kallsyms_markers");
    p_kallsyms_token_table = (void *)kallsyms_lookup_name("kallsyms_token_table");
    p_kallsyms_token_index = (void *)kallsyms_lookup_name("kallsyms_token_index");

    if (p_kallsyms_relative_base) {
        g_kallsyms_relative_base_val = *p_kallsyms_relative_base;
    }

    pr_info("[HEO-KPM] kallsyms: off=%d addr=%d names=%d tokens=%d relbase=0x%lx\n",
            !!p_kallsyms_offsets, !!p_kallsyms_addresses,
            !!p_kallsyms_names, !!p_kallsyms_token_table,
            g_kallsyms_relative_base_val);

    /* 7. Comm offset */
    resolve_task_comm_offset();

    /* 8. Scheduler hook */
    p_select_task_rq = (void *)kallsyms_lookup_name("select_task_rq");
    if (p_select_task_rq && g_comm_offset > 0) {
        hook_err_t h = hook_wrap4(p_select_task_rq, (void *)0, after_select_task_rq, (void *)0);
        if (!h) pr_info("[HEO-KPM] scheduler hook ACTIVE (comm offset 0x%x)\n", g_comm_offset);
        else    pr_warn("[HEO-KPM] hook_wrap4 ret=%d\n", h);
    }

    /* 9. prctl bridge */
    hook_err_t err = hook_syscalln(__NR_prctl, 5, before_prctl_hook, NULL, NULL);
    if (err) {
        pr_err("[HEO-KPM] hook_syscalln(prctl) failed: %d\n", err);
        return -1;
    }

    kpm_memset(g_fork_rules, 0, sizeof(g_fork_rules));

    pr_info("[HEO-KPM] ONLINE — tgid auth, chunked IO, true kallsyms 👑\n");
    return 0;
}

static long heo_companion_exit(void *reserved) {
    (void)reserved;
    pr_info("[HEO-KPM] unloading v6.0.0...\n");

    unhook_syscalln(__NR_prctl, before_prctl_hook, NULL);

    if (p_select_task_rq && g_comm_offset > 0)
        hook_unwrap(p_select_task_rq, (void *)0, after_select_task_rq);

    if (p_sched_latency && orig_sched_latency)             *p_sched_latency = orig_sched_latency;
    if (p_sched_min_gran && orig_sched_min_gran)           *p_sched_min_gran = orig_sched_min_gran;
    if (p_sched_wakeup_gran && orig_sched_wakeup_gran)     *p_sched_wakeup_gran = orig_sched_wakeup_gran;
    if (p_sched_migration_cost && orig_sched_migration_cost) *p_sched_migration_cost = orig_sched_migration_cost;

    for (int i = 0; i < 8; i++) {
        g_authorized_tgids[i] = 0;
        g_authorized_task_ptrs[i] = 0;
    }
    g_auth_idx = 0;

    pr_info("[HEO-KPM] clean exit.\n");
    return 0;
}

KPM_INIT(heo_companion_init);
KPM_EXIT(heo_companion_exit);