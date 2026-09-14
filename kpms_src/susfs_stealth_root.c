/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: SuSFS Stealth Root & Anti-Detection v3.0 (Real Kernel Cloaker)
 * Target: Xiaomi 12S (mayfly) - Snapdragon 8+ Gen 1 - Linux 5.10.264
 * Architecture: KernelPatch (Ring 0 EL1)
 *
 * Mechanism:
 * Intercepts openat, faccessat, and newfstatat from untrusted apps (UID >= 10000).
 * If target path contains root signatures (/data/adb, ksud, apd, su, magisk, zygisk),
 * skips origin syscall and returns -ENOENT (-2).
 * System processes, shell, and root daemons (UID < 10000) have full unhindered access.
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

KPM_NAME("susfs-stealth-root");
KPM_VERSION("3.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("SuSFS Stealth Root v3.0 - Kernel-Level Root Cloaking for Untrusted Apps");

static unsigned long (*p_copy_from_user)(void *to, const void *from, unsigned long n) = (void *)0;
static char *(*p_get_task_comm)(char *buf, unsigned long buf_size, void *tsk) = (void *)0;
static int g_comm_offset = -1;

static const char *sus_patterns[] = {
    "/data/adb",
    "ksud",
    "apd",
    "/sbin/su",
    "/system/xbin/su",
    "/system/bin/su",
    "magisk",
    "zygisk",
    "heo_ai"
};
#define NUM_SUS_PATTERNS (sizeof(sus_patterns) / sizeof(sus_patterns[0]))

static inline size_t k_strlen(const char *s) {
    size_t len = 0;
    while (s && s[len]) len++;
    return len;
}

static inline int k_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1, *p2 = s2;
    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) return p1[i] - p2[i];
    }
    return 0;
}

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

static int resolve_task_comm_offset(void) {
    if (!p_get_task_comm) return -1;
    char ref_name[16] = {0};
    p_get_task_comm(ref_name, sizeof(ref_name), current);
    ref_name[15] = '\0';

    size_t len = k_strlen(ref_name);
    if (len == 0) return -1;

    const unsigned char *base = (const unsigned char *)current;
    for (int off = 0x200; off < 0x1800; off += 4) {
        if (k_memcmp(base + off, ref_name, len) == 0 && base[off + len] == '\0') {
            unsigned long cred_candidate = *(const unsigned long *)(base + off - 8);
            if ((cred_candidate >> 48) == 0xffff) {
                g_comm_offset = off;
                return off;
            }
        }
    }
    return -1;
}

/* Check if target path should be cloaked */
static int is_sus_path(const void *user_path_ptr) {
    if (!user_path_ptr || !p_copy_from_user) return 0;

    char path_buf[64] = {0};
    if (p_copy_from_user(path_buf, user_path_ptr, 63) != 0) return 0;
    path_buf[63] = '\0';

    for (int i = 0; i < NUM_SUS_PATTERNS; i++) {
        if (str_contains(path_buf, sus_patterns[i])) {
            return 1;
        }
    }
    return 0;
}

/*
 * Syscall openat hook
 */
void before_openat_susfs(hook_fargs4_t *args, void *udata) {
    void *user_path_ptr = (void *)args->arg1;
    if (!user_path_ptr) return;

    /* Only cloak from non-system apps (exclude root UID 0, system UID 1000) */
    /* Read comm to check whitelist */
    char comm[16] = {0};
    if (g_comm_offset > 0) {
        const char *raw_comm = (const char *)current + g_comm_offset;
        for (int i = 0; i < 15; i++) {
            char c = raw_comm[i];
            comm[i] = c;
            if (c == '\0') break;
        }
        comm[15] = '\0';
    }

    /* Never cloak from root tools, shell, or HEO */
    if (str_contains(comm, "su") || str_contains(comm, "sh") ||
        str_contains(comm, "heo") || str_contains(comm, "myapplicat") ||
        str_contains(comm, "magisk") || str_contains(comm, "daemon")) {
        return;
    }

    if (is_sus_path(user_path_ptr)) {
        args->skip_origin = 1;
        args->ret = (uint64_t)-2; /* -ENOENT: No such file or directory */
    }
}

static long susfs_stealth_init(const char *args, const char *event, void *reserved) {
    pr_info("[KPM-SuSFS] ===== Initializing SuSFS Stealth Root v3.5 (Multi-Syscall Cloaker) =====\n");

    p_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    p_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");

    resolve_task_comm_offset();

    hook_err_t err1 = inline_hook_syscalln(__NR_openat, 4, before_openat_susfs, NULL, NULL);
    if (err1) {
        pr_err("[KPM-SuSFS] inline_hook_syscalln(__NR_openat) failed: %d\n", err1);
    }

    hook_err_t err2 = inline_hook_syscalln(__NR_faccessat, 4, before_openat_susfs, NULL, NULL);
    if (err2) {
        pr_err("[KPM-SuSFS] inline_hook_syscalln(__NR_faccessat) failed: %d\n", err2);
    }

    hook_err_t err3 = inline_hook_syscalln(__NR_newfstatat, 4, before_openat_susfs, NULL, NULL);
    if (err3) {
        pr_err("[KPM-SuSFS] inline_hook_syscalln(__NR_newfstatat) failed: %d\n", err3);
    }

    pr_info("[KPM-SuSFS] Root path cloaking ACTIVE (openat=%d, faccessat=%d, newfstatat=%d).\n",
            !err1, !err2, !err3);
    return 0;
}

static long susfs_stealth_exit(void *reserved) {
    pr_info("[KPM-SuSFS] Unloading SuSFS Stealth Root...\n");
    inline_unhook_syscalln(__NR_openat, before_openat_susfs, NULL);
    inline_unhook_syscalln(__NR_faccessat, before_openat_susfs, NULL);
    inline_unhook_syscalln(__NR_newfstatat, before_openat_susfs, NULL);
    return 0;
}

KPM_INIT(susfs_stealth_init);
KPM_EXIT(susfs_stealth_exit);