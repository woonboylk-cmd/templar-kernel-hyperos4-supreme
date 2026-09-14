/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: Pixel 11 Identity Spoofer — Minimal Hardened Edition v1.1
 * 3 hook: openat, openat2, readlinkat (after). 0 deref kernel. 0 scheduler.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <hook.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("pixel11-spoofer-min");
KPM_VERSION("1.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("vric & Antigravity");
KPM_DESCRIPTION("Pixel 11 Identity Spoofer Minimal Hardened v1.1 - 0 Kernel Deref, 0 Sched, Pure Extable Safe");

#ifndef __NR_openat
#define __NR_openat     56
#endif
#ifndef __NR_openat2
#define __NR_openat2    437
#endif
#ifndef __NR_readlinkat
#define __NR_readlinkat 78
#endif

#define SPOOF_PATH      "/data/adb/p11.prop"
#define SPOOF_PATH_LEN  18            /* strlen(SPOOF_PATH) */

/* Path giả để trả về khi ai đó readlink vào fd của p11.prop */
#define FAKE_PATH       "/system/build.prop"
#define FAKE_PATH_LEN  19            /* strlen(FAKE_PATH) */

/* Chỉ 2 symbol, đủ dùng */
static unsigned long (*p_cfu)(void *, const void *, unsigned long) = 0;
static unsigned long (*p_ctu)(void *, const void *, unsigned long) = 0;

/* ---------- helpers (không deref kernel pointer nào) ---------- */

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

static int starts_with(const char *p, const char *pfx) {
    while (*pfx) { if (*p++ != *pfx++) return 0; }
    return 1;
}

static int ends_with_build_prop(const char *p) {
    size_t n = s_len(p);
    if (n >= 11 && p[n-11]=='/' && p[n-10]=='b' && p[n-9]=='u' && p[n-8]=='i' &&
        p[n-7]=='l'  && p[n-6]=='d' && p[n-5]=='.' && p[n-4]=='p' &&
        p[n-3]=='r'  && p[n-2]=='o' && p[n-1]=='p')
        return 1;
    if (n == 10 && p[0]=='b' && p[1]=='u' && p[2]=='i' && p[3]=='l' &&
        p[4]=='d' && p[5]=='.' && p[6]=='p' && p[7]=='r' && p[8]=='o' && p[9]=='p')
        return 1;
    return 0;
}

static int path_excluded(const char *p) {
    return starts_with(p, "/vendor/")   ||
           starts_with(p, "/odm/")      ||
           starts_with(p, "/apex/")     ||
           starts_with(p, "/data/adb/");
}

/* /proc/.../fd/<N>  — không cần chính xác 100%, chỉ cần đúng dạng */
static int is_proc_fd_path(const char *p) {
    if (!starts_with(p, "/proc/")) return 0;
    /* tìm "/fd/" ở đâu đó */
    while (*p) {
        if (p[0]=='/' && p[1]=='f' && p[2]=='d' && p[3]=='/') return 1;
        p++;
    }
    return 0;
}

/* ---------- hook: openat / openat2 ---------- */

static void spoof_common(void *user_path_ptr) {
    if (!p_cfu || !p_ctu || !user_path_ptr) return;

    char path[96];
    if (p_cfu(path, user_path_ptr, sizeof(path) - 1) != 0) return;
    path[sizeof(path) - 1] = '\0';

    if (!ends_with_build_prop(path)) return;
    if (path_excluded(path))         return;

    /* Nếu user buffer < SPOOF_PATH_LEN+1: copy_to_user fail → caller nhận
     * -EFAULT, kernel không panic. An toàn. */
    p_ctu(user_path_ptr, SPOOF_PATH, SPOOF_PATH_LEN + 1);
}

static void before_openat(hook_fargs4_t *args, void *udata) {
    (void)udata;
    spoof_common((void *)args->arg1);
}

static void before_openat2(hook_fargs4_t *args, void *udata) {
    (void)udata;
    spoof_common((void *)args->arg1);
}

/* ---------- hook: readlinkat (after) ----------
 *
 * ssize_t readlinkat(int dfd, const char __user *path,
 *                    char __user *buf, int bufsiz);
 *   arg0 = dfd
 *   arg1 = path
 *   arg2 = buf (user)
 *   arg3 = bufsiz
 *   args->ret = bytes written (>=0) hoặc negative error
 *
 * Chạy SAU khi kernel đã fill buf. Nếu buf == "/data/adb/p11.prop",
 * ghi đè bằng "/system/build.prop" và cập nhật args->ret.
 */
static void after_readlinkat(hook_fargs4_t *args, void *udata) {
    (void)udata;
    if (!p_cfu || !p_ctu) return;

    long ret = (long)args->ret;
    if (ret <= 0 || ret > 200) return;          /* lỗi hoặc quá dài */

    void *user_path = (void *)args->arg1;
    void *user_buf  = (void *)args->arg2;
    size_t bufsiz   = (size_t)args->arg3;

    if (!user_path || !user_buf || bufsiz == 0) return;

    /* Chỉ can thiệp khi caller đọc /proc/.../fd/N */
    char path[64];
    if (p_cfu(path, user_path, sizeof(path) - 1) != 0) return;
    path[sizeof(path) - 1] = '\0';
    if (!is_proc_fd_path(path)) return;

    /* Đọc kết quả kernel vừa trả về (an toàn mảng 256 bytes) */
    char result[256];
    if ((size_t)ret >= sizeof(result)) ret = sizeof(result) - 1;
    if (p_cfu(result, user_buf, (unsigned long)ret) != 0) return;
    result[ret] = '\0';

    /* Nếu result là spoof path → thay bằng path giả */
    if (s_cmp(result, SPOOF_PATH) != 0) return;

    size_t copy_len = FAKE_PATH_LEN;
    if (copy_len > bufsiz) copy_len = bufsiz;    /* truncate nếu buffer nhỏ */

    if (p_ctu(user_buf, FAKE_PATH, copy_len) == 0) {
        args->ret = (uint64_t)copy_len;          /* cập nhật return value */
    }
}

/* ---------- resolve symbols with fallback ---------- */

static void resolve_symbols(void) {
    p_ctu = (void *)kallsyms_lookup_name("_copy_to_user");
    if (!p_ctu) p_ctu = (void *)kallsyms_lookup_name("raw_copy_to_user");
    if (!p_ctu) p_ctu = (void *)kallsyms_lookup_name("__arch_copy_to_user");

    p_cfu = (void *)kallsyms_lookup_name("_copy_from_user");
    if (!p_cfu) p_cfu = (void *)kallsyms_lookup_name("raw_copy_from_user");
    if (!p_cfu) p_cfu = (void *)kallsyms_lookup_name("__arch_copy_from_user");
}

/* ---------- init / exit ---------- */

static long init(const char *args, const char *event, void *reserved) {
    (void)args; (void)event; (void)reserved;

    resolve_symbols();
    if (!p_ctu || !p_cfu) {
        pr_err("[p11-min] copy_to/from_user unresolved\n");
        return -1;    /* thoát sạch, không hook gì */
    }

    inline_hook_syscalln(__NR_openat,      4, before_openat,     NULL, NULL);
    inline_hook_syscalln(__NR_openat2,     4, before_openat2,    NULL, NULL);
    inline_hook_syscalln(__NR_readlinkat,  4, NULL, after_readlinkat, NULL);

    pr_info("[p11-min] Pixel 11 Identity Spoofer Minimal Hardened v1.1 ACTIVE\n");
    return 0;
}

static long exit_fn(void *reserved) {
    (void)reserved;
    inline_unhook_syscalln(__NR_openat,     before_openat,  NULL);
    inline_unhook_syscalln(__NR_openat2,    before_openat2, NULL);
    inline_unhook_syscalln(__NR_readlinkat, NULL, after_readlinkat);
    pr_info("[p11-min] Pixel 11 Spoofer unloaded cleanly.\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit_fn);
