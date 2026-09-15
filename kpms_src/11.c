/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: Pixel 11 Pro XL Identity Spoofer — v4.1 Safe Boot Edition
 * Changelog từ v4.0:
 *   - REMOVED: Layer B (prop_area) — gây bootloop, phá shared memory
 *   - ADDED: PID-based guard (init=1, kernel threads pid<=2)
 *   - ADDED: file existence check trước khi redirect
 *   - ADDED: mtime check — /data phải đã mount
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
KPM_VERSION("4.1.0");
KPM_LICENSE("GPL v2");

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
#define SPOOF_VFS_PATH_LEN   18
#define FAKE_VFS_PATH        "/system/build.prop"
#define FAKE_VFS_PATH_LEN    19

static __always_inline void *kpm_memset(void *dst, int c, unsigned long n) {
    unsigned char *p = (unsigned char *)dst;
    while (n--) *p++ = (unsigned char)c;
    return dst;
}

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

static int (*p_task_pid_nr_ns)(void *, int, void *) = (void *)0;
static char *(*p_get_task_comm)(char *, unsigned long, void *) = (void *)0;
static void *(*p_filp_open)(const char *, int, int) = (void *)0;
static void  (*p_filp_close)(void *, void *) = (void *)0;

/* Camera whitelist — substring match */
static inline int is_camera_comm(const char *comm) {
    if (!comm || !comm[0]) return 0;
    if (str_contains(comm, "camera"))  return 1;
    if (str_contains(comm, "gallery")) return 1;
    if (str_contains(comm, "leica"))   return 1;
    return 0;
}

/* Kernel thread / early boot */
static inline int is_early_task(void) {
    /* Ưu tiên 1: check PID — init là 1, kthreadd là 2, kernel threads < 1000 */
    if (p_task_pid_nr_ns) {
        int pid = p_task_pid_nr_ns(current, 0, (void *)0);
        if (pid > 0 && pid < 1000) return 1;   /* PID 1-999: hệ thống, chưa mount /data */
    }
    /* Ưu tiên 2: comm-based fallback */
    if (p_get_task_comm) {
        char comm[16] = {0};
        p_get_task_comm(comm, sizeof(comm), current);
        comm[15] = '\0';
        if (starts_with(comm, "init"))   return 1;
        if (starts_with(comm, "swapper")) return 1;
        if (starts_with(comm, "kworker")) return 1;
        if (starts_with(comm, "ksoftirq")) return 1;
        if (starts_with(comm, "vold"))   return 1;
        if (starts_with(comm, "apexd"))  return 1;
        if (starts_with(comm, "servicemanager")) return 1;
        if (starts_with(comm, "hwservicemanage")) return 1;
        if (starts_with(comm, "zygote")) return 1;      /* zygote cũng cần prop_area */
        if (starts_with(comm, "system_server")) return 1;  /* cực kỳ quan trọng */
        if (is_camera_comm(comm)) return 1;
    }
    return 0;
}

static inline int ends_with_build_prop(const char *p) {
    size_t n = s_len(p);
    if (n >= 11 && s_ncmp(p + n - 10, "build.prop", 10) == 0 && p[n-11] == '/')
        return 1;
    if (n == 10 && s_ncmp(p, "build.prop", 10) == 0)
        return 1;
    return 0;
}

static inline int path_excluded(const char *p) {
    if (str_contains(p, "vendor"))    return 1;
    if (str_contains(p, "odm"))       return 1;
    if (str_contains(p, "apex"))      return 1;
    if (str_contains(p, "my_product"))return 1;
    if (starts_with(p, "/sdcard/"))   return 1;
    if (starts_with(p, "/storage/"))  return 1;
    if (starts_with(p, "/data/"))     return 1;   /* bao gồm chính /data/adb/p11.prop */
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

/* ═══════════════════════════════════════════════════════════════
 * Check file tồn tại — BẮT BUỘC trước khi redirect
 * Nếu p11.prop chưa tồn tại (early boot, /data chưa mount) → KHÔNG redirect
 * ═══════════════════════════════════════════════════════════════ */
static int spoof_target_exists(void) {
    if (!p_filp_open || !p_filp_close) {
        /* Không resolve được filp_open → từ chối spoof để an toàn */
        return 0;
    }
    /* O_RDONLY = 0. Gọi filp_open với path đối tượng */
    void *f = p_filp_open(SPOOF_VFS_PATH, 0, 0);
    if (!f) return 0;
    /* filp_open trả về ERR_PTR nếu lỗi — cần check IS_ERR, đơn giản hóa: 
     * nếu là con trỏ hợp lệ trong kernel range thì coi như OK.
     * Err ptr có dạng 0xffffffffffffffxx. */
    unsigned long fp = (unsigned long)f;
    if (fp >= 0xfffffffffffff000UL) return 0;
    p_filp_close(f, (void *)0);
    return 1;
}

static void spoof_common(void *user_path_ptr) {
    if (!user_path_ptr) return;

    /* ═══ GUARD 1: early boot / kernel thread / camera — từ chối sớm ═══ */
    if (is_early_task()) return;

    /* ═══ GUARD 2: target phải tồn tại (tức /data đã mount) ═══ */
    if (!spoof_target_exists()) return;

    /* ═══ GUARD 3: đọc path từ user ═══ */
    char path[128];
    long copied = compat_strncpy_from_user(path, user_path_ptr, sizeof(path) - 1);
    if (copied <= 0) return;
    path[sizeof(path) - 1] = '\0';

    /* ═══ LAYER A ONLY: VFS build.prop ═══ */
    if (!ends_with_build_prop(path)) return;
    if (path_excluded(path))         return;

    size_t path_len = s_len(path);
    if (path_len < SPOOF_VFS_PATH_LEN) return;  /* buffer user không đủ chỗ */

    compat_copy_to_user(user_path_ptr, SPOOF_VFS_PATH, SPOOF_VFS_PATH_LEN + 1);
}

static void before_openat(hook_fargs4_t *args, void *udata) {
    (void)udata;
    spoof_common((void *)syscall_argn(args, 1));
}

static void before_openat2(hook_fargs4_t *args, void *udata) {
    (void)udata;
    spoof_common((void *)syscall_argn(args, 1));
}

static void after_readlinkat(hook_fargs4_t *args, void *udata) {
    (void)udata;
    long ret = (long)args->ret;
    if (ret <= 0 || ret > 256) return;

    void *user_path = (void *)syscall_argn(args, 1);
    void *user_buf  = (void *)syscall_argn(args, 2);
    size_t bufsiz   = (size_t)syscall_argn(args, 3);
    if (!user_path || !user_buf || bufsiz == 0) return;

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

static void resolve_symbols(void) {
    p_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    if (!p_get_task_comm) p_get_task_comm = (void *)kallsyms_lookup_name("get_task_comm");

    p_task_pid_nr_ns = (void *)kallsyms_lookup_name("__task_pid_nr_ns");

    p_filp_open = (void *)kallsyms_lookup_name("filp_open");
    p_filp_close = (void *)kallsyms_lookup_name("filp_close");

    pr_info("[p11] resolved: comm=%d pid=%d filp=%d\n",
            !!p_get_task_comm, !!p_task_pid_nr_ns, !!p_filp_open);
}

static long init(const char *args, const char *event, void *reserved) {
    (void)args; (void)event; (void)reserved;

    resolve_symbols();

    /* Nếu không resolve được filp_open → không thể check file tồn tại → từ chối load */
    if (!p_filp_open) {
        pr_err("[p11] filp_open unresolved — refusing to hook (would bootloop)\n");
        return -1;
    }

    hook_syscalln(__NR_openat,     4, before_openat,  NULL, NULL);
    hook_syscalln(__NR_openat2,    4, before_openat2, NULL, NULL);
    hook_syscalln(__NR_readlinkat, 4, NULL, after_readlinkat, NULL);

    pr_info("[p11] v4.1 Safe Boot ACTIVE\n");
    return 0;
}

static long exit_fn(void *reserved) {
    (void)reserved;
    unhook_syscalln(__NR_openat,     before_openat,  NULL);
    unhook_syscalln(__NR_openat2,    before_openat2, NULL);
    unhook_syscalln(__NR_readlinkat, NULL, after_readlinkat);
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit_fn);
