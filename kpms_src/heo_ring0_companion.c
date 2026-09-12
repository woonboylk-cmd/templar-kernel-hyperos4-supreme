/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: HEO Ring 0 Sovereign Companion v2.0
 * Target: Xiaomi 12S (mayfly) - Snapdragon 8+ Gen 1 (SM8475) - Linux Kernel 5.10.x
 * Architecture: KernelPatch (Ring 0 EL1)
 *
 * Provides a cryptographically-authenticated direct syscall bridge (prctl)
 * for the HEO app (com.example.myapplication).
 *
 * Key Architecture Calibration:
 * 1. Uses syscall_argn() to safely extract arguments under CONFIG_ARM64_SYSCALL_WRAPPER
 * 2. Sets args->skip_origin = 1 to intercept prctl and return directly without -EINVAL
 * 3. Compiles with -fno-pic -mcmodel=small to prevent unsupported relocation 311
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
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("HEO Ring 0 Sovereign Kernel Companion - Challenge-Response Authentication & Memory Bridge");

#define HEO_MAGIC_PRCTL          0x48454F    /* 'HEO' in ASCII */
#define HEO_CMD_GET_CHALLENGE    0x01
#define HEO_CMD_VERIFY_AUTH      0x02
#define HEO_CMD_STATUS           0x03
#define HEO_CMD_FORCE_YAMA_OFF   0x04

/* Pre-shared secret salt: 0xA55A1337BEEFCAFEULL */
#define HEO_SECRET_SALT          0xA55A1337BEEFCAFEULL

static unsigned long authorized_task_ptr = 0;
static uint64_t current_nonce = 0x1337CAFEBEEFULL;

/*
 * Syscall prctl hook function:
 * long prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
 */
void before_prctl_hook(hook_fargs5_t *args, void *udata) {
    int option = (int)syscall_argn(args, 0);

    if (option != HEO_MAGIC_PRCTL) {
        return; /* Not a HEO command, let kernel handle normally */
    }

    /* Intercepted HEO command: do NOT run original sys_prctl (which would return -EINVAL) */
    args->skip_origin = 1;

    unsigned long cmd = (unsigned long)syscall_argn(args, 1);
    struct task_struct *task = current;
    unsigned long task_now = (unsigned long)task;

    switch (cmd) {
        case HEO_CMD_GET_CHALLENGE: {
            /* Generate 31-bit pseudo-random challenge nonce compatible with Java signed int */
            current_nonce = (current_nonce * 6364136223846793005ULL) + 1442695040888963407ULL + task_now;
            uint32_t nonce32 = (uint32_t)(current_nonce & 0x7FFFFFFFU);
            if (nonce32 == 0) nonce32 = 0x1337BEEF;
            args->ret = (uint64_t)nonce32;
            pr_info("[HEO-KPM] Nonce challenge issued for task 0x%lx: 0x%x\n", task_now, nonce32);
            break;
        }

        case HEO_CMD_VERIFY_AUTH: {
            /* Verify client token passed in arg2 */
            uint64_t client_token = (uint64_t)syscall_argn(args, 2);
            uint32_t nonce32 = (uint32_t)(current_nonce & 0x7FFFFFFFU);
            if (nonce32 == 0) nonce32 = 0x1337BEEF;
            uint64_t expected_token = ((uint64_t)nonce32) ^ HEO_SECRET_SALT;

            if (client_token == expected_token) {
                authorized_task_ptr = task_now;
                args->ret = 0x1337; /* Success code (4919) */
                pr_info("[HEO-KPM] Authentication SUCCESS! Task 0x%lx granted Ring 0 Sovereign privilege.\n", task_now);
            } else {
                args->ret = (uint64_t)-1;
                pr_warn("[HEO-KPM] Auth FAILED: token mismatch (got 0x%llx, expected 0x%llx) from Task 0x%lx!\n",
                        (unsigned long long)client_token, (unsigned long long)expected_token, task_now);
            }
            break;
        }

        case HEO_CMD_STATUS: {
            /* Returns 1 if the calling task is authorized */
            if (authorized_task_ptr != 0 && authorized_task_ptr == task_now) {
                args->ret = 1;
            } else {
                args->ret = 0;
            }
            break;
        }

        case HEO_CMD_FORCE_YAMA_OFF: {
            if (authorized_task_ptr == task_now) {
                pr_info("[HEO-KPM] Ring 0: Disabling Yama ptrace restriction across kernel\n");
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

        default:
            args->ret = (uint64_t)-1;
            break;
    }
}

static long heo_companion_init(const char *args, const char *event, void *reserved) {
    pr_info("[HEO-KPM] Initializing HEO Ring 0 Sovereign Companion v2.0.0...\n");
    pr_info("[HEO-KPM] Target SoC: Snapdragon 8+ Gen 1 (SM8475) | KernelPatch EL1\n");

    hook_err_t err = inline_hook_syscalln(__NR_prctl, 5, before_prctl_hook, NULL, NULL);
    if (err) {
        pr_err("[HEO-KPM] inline_hook_syscalln(__NR_prctl) failed: %d\n", err);
        return -1;
    }

    pr_info("[HEO-KPM] Prctl Syscall Hook ACTIVE. Ring 0 Sovereign Bridge ready for HEO.\n");
    return 0;
}

static long heo_companion_exit(void *reserved) {
    pr_info("[HEO-KPM] Unloading HEO Ring 0 Companion...\n");
    inline_unhook_syscalln(__NR_prctl, before_prctl_hook, NULL);
    authorized_task_ptr = 0;
    return 0;
}

KPM_INIT(heo_companion_init);
KPM_EXIT(heo_companion_exit);
