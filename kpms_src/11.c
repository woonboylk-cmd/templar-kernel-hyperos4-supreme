/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: Pixel 11 Pro XL Identity Spoofer — v4.3 Hardened Safe Boot
 * Target: Xiaomi 12S (mayfly) - Snapdragon 8+ Gen 1 (SM8475) - Linux 5.10.x
 *
 * Base: v4.2 (verified boot OK trên máy thật)
 *
 * Changelog so với v4.2:
 *   [ADD] Extended comm guard:
 *         - servicemanager, hwservicemanager
 *         - zygote, system_server, surfaceflinger, bootanim
 *         - keystore, logd, netd
 *         - HALs: hardware, vendor.qti, vendor.xiaomi
 *   [ADD] Fail-closed: nếu get_task_comm không resolve → không hook gì
 *   [ADD] VA ceiling 47-bit (tương thích cả 39-bit và 48-bit kernel)
 *   [ADD] Boundary check trong readlinkat (bufsiz > 0, VA hợp lệ)
 *   [ADD] Exclude /my_product/ (MIUI partition) khỏi spoof
 *   [KEPT] KHÔNG có filp_open — đã chứng minh gây bootloop ở v4.1
 *   [KEPT] Chỉ 3 syscall hook: openat, openat2, readlinkat
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

KPM_NAME("pixel11-spoofer");
KPM_VERSION("4.3.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("Pixel 11 Pro XL Identity Spoofer v4.3 — Hardened Safe Boot, extended guard, no filp_open");

#ifndef __NR_openat
#define __NR_openat     56
#endif
#ifndef __NR_openat2
#define __NR_openat2    437
#endif
#ifndef __NR_readlinkat
#define __NR_readlinkat 78
#endif

#define SPOOF_VFS_PATH       "/data/adb/p11.prop"
#define SPOOF_VFS_PATH_LEN   18            /* strlen(SPOOF_VFS_PATH) */
#define FAKE_VFS_PATH        "/system/build.prop"
#define FAKE_VFS_PATH_LEN    19            /* strlen(FAKE_VFS_PATH) */

/* ───── Inlined memory helpers (GOT 311 safe, zero external BL) ───── */

static __always_inline void *kpm_memset(void *dst, int c, unsigned long n) {
    unsigned char *p = (unsigned char *)dst;
    while (n--) *p++ = (unsigned char)c;
    return dst;
}

/* ───── Freestanding string helpers ───── */

static inline size_t s_len(const char *s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static inline int s_cmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static inline int s_ncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

static inline int starts_with(const char *p, const char *pfx) {
    if (!p || !pfx) return 0;
    while (*pfx) { if (*p++ != *pfx++) return 0; }
    return 1;
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

/* ───── Kernel symbol pointers ───── */

static char *(*p_get_task_comm)(char *buf, unsigned long buf_size, void *tsk) = (void *)0;

/* ───── VA guard: 47-bit ceiling — an toàn cho cả 39-bit và 48-bit VA ───── */

static inline int is_valid_user_addr(const void *addr, unsigned long n) {
    unsigned long a = (unsigned long)addr;
    if (a == 0) return 0;
    /* 0x0001000000000000 = 2^48: user VA luôn < ngưỡng này */
    if (a >= 0x0001000000000000UL) return 0;
    /* Overflow check */
    if (n > 0 && (a + n) < a) return 0;
    return 1;
}

/* ───── Extended comm guard ─────
 *
 * FAIL-CLOSED: nếu p_get_task_comm không resolve → coi như early task → không spoof.
 * Điều này đảm bảo nếu symbol không có (kernel config khác), module không gây hại.
 */
static inline int is_early_task(void) {
    /* FAIL-CLOSED */
    if (!p_get_task_comm) return 1;

    char comm[16] = {0};
    p_get_task_comm(comm, sizeof(comm), current);
    comm[15] = '\0';

    /* Kernel threads */
    if (starts_with(comm, "init"))         return 1;
    if (starts_with(comm, "swapper"))      return 1;
    if (starts_with(comm, "kworker"))      return 1;
    if (starts_with(comm, "ksoftirq"))     return 1;
    if (starts_with(comm, "kthreadd"))     return 1;

    /* Boot daemons */
    if (starts_with(comm, "vold"))         return 1;
    if (starts_with(comm, "apexd"))        return 1;
    if (starts_with(comm, "logd"))         return 1;
    if (starts_with(comm, "netd"))         return 1;
    if (starts_with(comm, "keystore"))     return 1;
    if (starts_with(comm, "servicemanager")) return 1;
    if (starts_with(comm, "hwservicemanage")) return 1;

    /* Android framework core (draw logo MI, boot UI) */
    if (starts_with(comm, "zygote"))       return 1;
    if (starts_with(comm, "system_server")) return 1;
    if (starts_with(comm, "surfaceflinger")) return 1;
    if (starts_with(comm, "bootanim"))     return 1;

    /* HALs — tên process thường dài và bị truncate, dùng substring */
    if (str_contains(comm, "hardware"))    return 1;
    if (str_contains(comm, "vendor.qti"))  return 1;
    if (str_contains(comm, "vendor.xiaomi")) return 1;

    /* Camera / gallery / leica whitelist */
    if (str_contains(comm, "camera"))      return 1;
    if (str_contains(comm, "gallery"))     return 1;
    if (str_contains(comm, "leica"))       return 1;

    return 0;
}

/* ───── Path matching ───── */

static inline int ends_with_build_prop(const char *p) {
    size_t n = s_len(p);
    if (n >= 11 && s_ncmp(p + n - 10, "build.prop", 10) == 0 && p[n-11] == '/')
        return 1;
    if (n == 10 && s_ncmp(p, "build.prop", 10) == 0)
        return 1;
    return 0;
}

static inline int path_excluded(const char *p) {
    if (str_contains(p, "vendor"))     return 1;
    if (str_contains(p, "odm"))        return 1;
    if (str_contains(p, "apex"))       return 1;
    if (str_contains(p, "my_product")) return 1;   /* MIUI partition */
    if (starts_with(p, "/sdcard/"))    return 1;
    if (starts_with(p, "/storage/"))   return 1;
    if (starts_with(p, "/data/"))      return 1;
    return 0;
}

static inline int is_proc_fd_path(const char *p) {
    if (!starts_with(p, "/proc/")) return 0;
    while (*p) {
        if (p[0]=='/' && p[1]=='f' && p[2]=='d' && p[3]=='/') return 1;
        p++;
    }
    return 0;
}

/* ───── Master spoof logic ─────
 *
 * THỨ TỰ QUAN TRỌNG: path check TRƯỚC, tuyệt đối không có I/O call trước path check.
 * Đây là bài học từ v4.1 (filp_open trước path check → bootloop).
 */

static void spoof_common(void *user_path_ptr) {
    if (!is_valid_user_addr(user_path_ptr, 1)) return;
    if (is_early_task()) return;

    char path[128];
    long copied = compat_strncpy_from_user(path, user_path_ptr, sizeof(path) - 1);
    if (copied <= 0) return;
    path[sizeof(path) - 1] = '\0';

    /* Path check TRƯỚC mọi thao tác khác */
    if (!ends_with_build_prop(path)) return;
    if (path_excluded(path))         return;

    /* Boundary: buffer user phải đủ chỗ cho SPOOF_VFS_PATH + NUL */
    if (s_len(path) < SPOOF_VFS_PATH_LEN) return;

    /* In-place redirect — copy_to_user fail → caller nhận -EFAULT, kernel không panic */
    compat_copy_to_user(user_path_ptr, SPOOF_VFS_PATH, SPOOF_VFS_PATH_LEN + 1);
}

/* ───── Syscall hooks ───── */

static void before_openat(hook_fargs4_t *args, void *udata) {
    (void)udata;
    spoof_common((void *)syscall_argn(args, 1));
}

static void before_openat2(hook_fargs4_t *args, void *udata) {
    (void)udata;
    spoof_common((void *)syscall_argn(args, 1));
}

/* readlinkat (after) — che /proc/PID/fd/N leak */
static void after_readlinkat(hook_fargs4_t *args, void *udata) {
    (void)udata;

    long ret = (long)args->ret;
    if (ret <= 0 || ret > 256) return;

    void *user_path = (void *)syscall_argn(args, 1);
    void *user_buf  = (void *)syscall_argn(args, 2);
    unsigned long bufsiz = (unsigned long)syscall_argn(args, 3);

    if (!is_valid_user_addr(user_path, 1)) return;
    if (!is_valid_user_addr(user_buf, 1)) return;
    if (bufsiz == 0) return;

    char path[64];
    long copied = compat_strncpy_from_user(path, user_path, sizeof(path) - 1);
    if (copied <= 0) return;
    path[sizeof(path) - 1] = '\0';
    if (!is_proc_fd_path(path)) return;

    char result[256];
    if ((size_t)ret >= sizeof(result)) ret = sizeof(result) - 1;
    if (compat_strncpy_from_user(result, user_buf, ret) <= 0) return;
    result[ret] = '\0';

    if (s_cmp(result, SPOOF_VFS_PATH) != 0) return;

    size_t copy_len = FAKE_VFS_PATH_LEN;
    if (copy_len > bufsiz) copy_len = bufsiz;
    if (compat_copy_to_user(user_buf, FAKE_VFS_PATH, copy_len) == 0)
        args->ret = (uint64_t)copy_len;
}

/* ───── Lifecycle ───── */

static long init(const char *args, const char *event, void *reserved) {
    (void)args; (void)event; (void)reserved;

    p_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    if (!p_get_task_comm) p_get_task_comm = (void *)kallsyms_lookup_name("get_task_comm");

    /* Fail-closed: không có comm resolver → không hook gì cả */
    if (!p_get_task_comm) {
        pr_err("[p11] get_task_comm unresolved — refusing to hook (fail-closed)\n");
        return -1;
    }

    hook_syscalln(__NR_openat,     4, before_openat,  NULL, NULL);
    hook_syscalln(__NR_openat2,    4, before_openat2, NULL, NULL);
    hook_syscalln(__NR_readlinkat, 4, NULL, after_readlinkat, NULL);

    pr_info("[p11] v4.3 Hardened Safe Boot ACTIVE\n");
    return 0;
}

static long exit_fn(void *reserved) {
    (void)reserved;
    unhook_syscalln(__NR_openat,     before_openat,  NULL);
    unhook_syscalln(__NR_openat2,    before_openat2, NULL);
    unhook_syscalln(__NR_readlinkat, NULL, after_readlinkat);
    pr_info("[p11] v4.3 unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit_fn);
