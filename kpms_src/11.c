/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: Pixel 11 Pro XL Identity & Prop-Area Spoofer — Hardened Edition v4.0
 * Target: Xiaomi 12S (mayfly) - Snapdragon 8+ Gen 1 (SM8475) - Linux 5.10.x
 * Architecture: KernelPatch (Ring 0 EL1)
 *
 * Full Feature Matrix:
 * 1. Dual-Layer Spoofing:
 *    - Layer A (VFS): Intercepts /system/build.prop -> /data/adb/p11.prop
 *    - Layer B (RAM prop_area): Intercepts /dev/__properties__/u:object_r:build_prop:s0
 *      and /dev/__properties__/u:object_r:default_prop:s0 -> /data/adb/p11_props_area
 * 2. Standard Syscall Arg Extraction: Strictly uses syscall_argn() for pt_regs on ARM64 GKI.
 * 3. Early-Boot & Daemon Guard: Bypasses init (PID 1), swapper, vold, apexd before /data is ready.
 * 4. Leica Camera Whitelist: Camera, gallery, and camera HALs always read genuine Xiaomi props.
 * 5. Boundary Protection: Never overwrites userspace buffers smaller than target path length.
 * 6. Zero GOT 311/312 Relocations: Pure inlined memory helpers, zero external BL compiler calls.
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
KPM_VERSION("4.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("Pixel 11 Pro XL Dual-Layer Identity & Prop-Area Spoofer v4.0 (VFS + RAM prop_area)");

#ifndef __NR_openat
#define __NR_openat     56
#endif
#ifndef __NR_openat2
#define __NR_openat2    437
#endif
#ifndef __NR_readlinkat
#define __NR_readlinkat 78
#endif

/* Layer A: VFS File Spoof */
#define SPOOF_VFS_PATH       "/data/adb/p11.prop"
#define SPOOF_VFS_PATH_LEN   18            /* strlen(SPOOF_VFS_PATH) */
#define FAKE_VFS_PATH        "/system/build.prop"
#define FAKE_VFS_PATH_LEN    19            /* strlen(FAKE_VFS_PATH) */

/* Layer B: RAM Shared Memory prop_area Spoof */
#define SPOOF_PROP_AREA_PATH     "/data/adb/p11_props_area"
#define SPOOF_PROP_AREA_PATH_LEN 24        /* strlen(SPOOF_PROP_AREA_PATH) */

/* Inlined freestanding memory helpers (Zero compiler BL calls, Zero GOT relocations) */
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
        while (*h_sub && *n_sub && (*h_sub == *n_sub)) {
            h_sub++;
            n_sub++;
        }
        if (!*n_sub) return 1;
        h++;
    }
    return 0;
}

/* Fallback pointers for kernel task comm */
static char *(*p_get_task_comm)(char *buf, unsigned long buf_size, void *tsk) = (void *)0;

/* Leica Camera & Hardware Whitelist (Protected from spoofing) */
static const char *camera_whitelist[] = {
    "camera",
    "cameraserver",
    "media.camera",
    "qti.camera",
    "vtcamera",
    "vendor.qti.camera",
    "vendor.xiaomi.hardware.camera",
    "android.hardware.camera",
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

/* Early-boot & system daemon protection: NEVER spoof init (PID 1) or low-level daemons */
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
    if (n >= 11 && s_ncmp(p + n - 10, "build.prop", 10) == 0 && p[n-11] == '/')
        return 1;
    if (n == 10 && s_ncmp(p, "build.prop", 10) == 0)
        return 1;
    return 0;
}

static inline int is_prop_area_target(const char *p) {
    if (!starts_with(p, "/dev/__properties__/")) return 0;
    if (str_contains(p, "build_prop") || str_contains(p, "default_prop"))
        return 1;
    return 0;
}

static inline int path_excluded(const char *p) {
    if (str_contains(p, "vendor"))           return 1;
    if (str_contains(p, "odm"))              return 1;
    if (str_contains(p, "apex"))             return 1;
    if (starts_with(p, "/sdcard/"))          return 1;
    if (starts_with(p, "/storage/"))         return 1;
    if (starts_with(p, "/data/adb/"))        return 1;
    if (s_cmp(p, SPOOF_VFS_PATH) == 0)       return 1;
    if (s_cmp(p, SPOOF_PROP_AREA_PATH) == 0) return 1;
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

/* ---------- Master Dual-Layer Spoof Logic ---------- */

static void spoof_common(void *user_path_ptr) {
    if (!user_path_ptr) return;

    /* Filter 1: Check caller task comm */
    if (p_get_task_comm) {
        char comm[16] = {0};
        p_get_task_comm(comm, sizeof(comm), current);
        comm[15] = '\0';
        if (is_early_boot_daemon(comm)) return;
        if (is_whitelisted_camera(comm)) return;
    }

    char path[128];
    long copied = compat_strncpy_from_user(path, user_path_ptr, sizeof(path) - 1);
    if (copied <= 0) return;
    path[sizeof(path) - 1] = '\0';

    /* Check Layer B: RAM Shared Memory prop_area interception */
    if (is_prop_area_target(path)) {
        size_t path_len = s_len(path);
        /* /dev/__properties__/u:object_r:build_prop:s0 is 44 bytes, target is 24 bytes */
        if (path_len >= SPOOF_PROP_AREA_PATH_LEN) {
            compat_copy_to_user(user_path_ptr, SPOOF_PROP_AREA_PATH, SPOOF_PROP_AREA_PATH_LEN + 1);
            return;
        }
    }

    /* Check Layer A: VFS build.prop interception */
    if (ends_with_build_prop(path) && !path_excluded(path)) {
        size_t path_len = s_len(path);
        if (path_len >= SPOOF_VFS_PATH_LEN) {
            compat_copy_to_user(user_path_ptr, SPOOF_VFS_PATH, SPOOF_VFS_PATH_LEN + 1);
            return;
        }
    }
}

/* Syscall Hooks using syscall_argn() on ARM64 pt_regs */
static void before_openat(hook_fargs4_t *args, void *udata) {
    (void)udata;
    void *user_path_ptr = (void *)syscall_argn(args, 1);
    spoof_common(user_path_ptr);
}

static void before_openat2(hook_fargs4_t *args, void *udata) {
    (void)udata;
    void *user_path_ptr = (void *)syscall_argn(args, 1);
    spoof_common(user_path_ptr);
}

/* Hook readlinkat (after): Hide /data/adb/p11.prop from /proc/PID/fd inspection */
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

    if (s_cmp(result, SPOOF_VFS_PATH) == 0) {
        size_t copy_len = FAKE_VFS_PATH_LEN;
        if (copy_len > bufsiz) copy_len = bufsiz;
        if (compat_copy_to_user(user_buf, FAKE_VFS_PATH, copy_len) == 0) {
            args->ret = (uint64_t)copy_len;
        }
    }
}

/* ---------- Symbols & Lifecycle ---------- */

static void resolve_symbols(void) {
    p_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    if (!p_get_task_comm) p_get_task_comm = (void *)kallsyms_lookup_name("get_task_comm");
}

static long init(const char *args, const char *event, void *reserved) {
    (void)args; (void)event; (void)reserved;

    resolve_symbols();

    /* Use hook_syscalln: auto-adapts between fp_hook and inline_hook */
    hook_syscalln(__NR_openat,     4, before_openat,  NULL, NULL);
    hook_syscalln(__NR_openat2,    4, before_openat2, NULL, NULL);
    hook_syscalln(__NR_readlinkat, 4, NULL, after_readlinkat, NULL);

    pr_info("[p11-spoofer] Pixel 11 Pro XL Dual-Layer Identity & Prop-Area Spoofer v4.0 ACTIVE 👑\n");
    return 0;
}

static long exit_fn(void *reserved) {
    (void)reserved;
    unhook_syscalln(__NR_openat,     before_openat,  NULL);
    unhook_syscalln(__NR_openat2,    before_openat2, NULL);
    unhook_syscalln(__NR_readlinkat, NULL, after_readlinkat);
    pr_info("[p11-spoofer] Pixel 11 Spoofer unloaded cleanly.\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit_fn);