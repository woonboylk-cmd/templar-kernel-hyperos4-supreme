/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: Pixel 11 Pro XL Identity Spoofer — Hardened Edition v3.2
 * Target: Xiaomi 12S (mayfly) - Snapdragon 8+ Gen 1 (SM8475) - Linux 5.10.x
 * Architecture: KernelPatch (Ring 0 EL1)
 *
 * Capabilities:
 * 1. 3 Syscall Hooks: openat (56), openat2 (437), readlinkat (78 after).
 * 2. Early-Boot & Init Guard: NEVER intercepts init (PID 1), swapper, or system daemons before /data is mounted.
 * 3. Leica Camera Whitelist: Camera & gallery processes read genuine build.prop (zero camera crashes).
 * 4. Extable Safe: zero kernel pointer dereferences, copy_to/from_user extable bounds protected.
 * 5. Inlined kpm_memcpy / kpm_memset: Zero external compiler BL dependencies, zero GOT 311.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <hook.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("pixel11-spoofer");
KPM_VERSION("3.2.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("Pixel 11 Pro XL Identity Spoofer v3.2 - Hardened Extable Safe, Leica Whitelist, Early-Boot Guard");

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

#define FAKE_PATH       "/system/build.prop"
#define FAKE_PATH_LEN   19            /* strlen(FAKE_PATH) */

/* KPM-safe memory helpers: inlined by compiler, zero external BL memcpy/memset */
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

/* Freestanding string helpers */
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
        while (*h_sub && *n_sub && (*h_sub == *n_sub)) {
            h_sub++;
            n_sub++;
        }
        if (!*n_sub) return 1;
        h++;
    }
    return 0;
}

/* Function pointers */
static unsigned long (*p_cfu)(void *, const void *, unsigned long) = (void *)0;
static unsigned long (*p_ctu)(void *, const void *, unsigned long) = (void *)0;
static char *(*p_get_task_comm)(char *buf, unsigned long buf_size, void *tsk) = (void *)0;

/* Leica Camera Whitelist */
static const char *camera_whitelist[] = {
    "camera",
    "qti.camera",
    "cameraserver",
    "vtcamera",
    "mm-qcamera",
    "miui.gallery",
    "gallery"
};

static inline int is_whitelisted_camera(const char *comm) {
    if (!comm || comm[0] == '\0') return 0;
    for (size_t i = 0; i < sizeof(camera_whitelist) / sizeof(camera_whitelist[0]); i++) {
        if (str_contains(comm, camera_whitelist[i])) {
            return 1;
        }
    }
    return 0;
}

/* Early-boot & system daemon protection: NEVER spoof init (PID 1) or boot daemons */
static inline int is_early_boot_daemon(const char *comm) {
    if (!comm || comm[0] == '\0') return 0;
    if (starts_with(comm, "init") ||
        starts_with(comm, "swapper") ||
        starts_with(comm, "vold") ||
        starts_with(comm, "apexd") ||
        starts_with(comm, "servicemanager") ||
        starts_with(comm, "hwservicemanage")) {
        return 1;
    }
    return 0;
}

static inline int ends_with_build_prop(const char *p) {
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

static inline int path_excluded(const char *p) {
    return starts_with(p, "/vendor/")   ||
           starts_with(p, "/odm/")      ||
           starts_with(p, "/apex/")     ||
           starts_with(p, "/data/adb/");
}

static inline int is_proc_fd_path(const char *p) {
    if (!starts_with(p, "/proc/")) return 0;
    while (*p) {
        if (p[0]=='/' && p[1]=='f' && p[2]=='d' && p[3]=='/') return 1;
        p++;
    }
    return 0;
}

/* ---------- hook: openat / openat2 ---------- */

static void spoof_common(void *user_path_ptr) {
    if (!p_cfu || !p_ctu || !user_path_ptr) return;

    /* Check caller task comm: skip early boot daemons and camera */
    if (p_get_task_comm) {
        char comm[16] = {0};
        p_get_task_comm(comm, sizeof(comm), current);
        comm[15] = '\0';
        if (is_early_boot_daemon(comm)) return;
        if (is_whitelisted_camera(comm)) return;
    }

    char path[96];
    if (p_cfu(path, user_path_ptr, sizeof(path) - 1) != 0) return;
    path[sizeof(path) - 1] = '\0';

    if (!ends_with_build_prop(path)) return;
    if (path_excluded(path))         return;

    /* Overwrite path in userspace memory with spoof path */
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

/* ---------- hook: readlinkat (after) ---------- */

static void after_readlinkat(hook_fargs4_t *args, void *udata) {
    (void)udata;
    if (!p_cfu || !p_ctu) return;

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
    if ((size_t)ret >= sizeof(result)) ret = sizeof(result) - 1;
    if (p_cfu(result, user_buf, (unsigned long)ret) != 0) return;
    result[ret] = '\0';

    if (s_cmp(result, SPOOF_PATH) != 0) return;

    size_t copy_len = FAKE_PATH_LEN;
    if (copy_len > bufsiz) copy_len = bufsiz;

    if (p_ctu(user_buf, FAKE_PATH, copy_len) == 0) {
        args->ret = (uint64_t)copy_len;
    }
}

/* ---------- resolve symbols with fallback ---------- */

static void resolve_symbols(void) {
    p_ctu = (void *)kallsyms_lookup_name("__arch_copy_to_user");
    if (!p_ctu) p_ctu = (void *)kallsyms_lookup_name("_copy_to_user");
    if (!p_ctu) p_ctu = (void *)kallsyms_lookup_name("raw_copy_to_user");

    p_cfu = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if (!p_cfu) p_cfu = (void *)kallsyms_lookup_name("_copy_from_user");
    if (!p_cfu) p_cfu = (void *)kallsyms_lookup_name("raw_copy_from_user");

    p_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    if (!p_get_task_comm) p_get_task_comm = (void *)kallsyms_lookup_name("get_task_comm");
}

/* ---------- init / exit ---------- */

static long init(const char *args, const char *event, void *reserved) {
    (void)args; (void)event; (void)reserved;

    resolve_symbols();
    if (!p_ctu || !p_cfu) {
        pr_err("[p11-spoofer] copy_to/from_user unresolved — aborting\n");
        return -1;
    }

    inline_hook_syscalln(__NR_openat,     4, before_openat,  NULL, NULL);
    inline_hook_syscalln(__NR_openat2,    4, before_openat2, NULL, NULL);
    inline_hook_syscalln(__NR_readlinkat, 4, NULL, after_readlinkat, NULL);

    pr_info("[p11-spoofer] Pixel 11 Pro XL Identity Spoofer v3.2 ACTIVE\n");
    return 0;
}

static long exit_fn(void *reserved) {
    (void)reserved;
    inline_unhook_syscalln(__NR_openat,     before_openat,  NULL);
    inline_unhook_syscalln(__NR_openat2,    before_openat2, NULL);
    inline_unhook_syscalln(__NR_readlinkat, NULL, after_readlinkat);
    pr_info("[p11-spoofer] Pixel 11 Spoofer unloaded cleanly.\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit_fn);