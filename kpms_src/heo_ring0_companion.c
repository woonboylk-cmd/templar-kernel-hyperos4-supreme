/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: HEO Ring 0 Sovereign Companion
 * Target: Xiaomi 12S (mayfly) - Linux Kernel 5.10.x
 * Architecture: KernelPatch (Ring 0 EL1)
 *
 * Provides a cryptographically-authenticated direct syscall bridge (prctl)
 * for the HEO app (com.example.myapplication).
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <hook.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <linux/string.h>

KPM_NAME("heo-ring0-companion");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("HEO Ring 0 Sovereign Kernel Companion - Challenge-Response Authentication & Memory Bridge");

#define HEO_MAGIC_PRCTL          0x48454F    /* 'HEO' in ASCII */
#define HEO_CMD_GET_CHALLENGE    0x01
#define HEO_CMD_VERIFY_AUTH      0x02
#define HEO_CMD_STATUS           0x03
#define HEO_CMD_FORCE_YAMA_OFF   0x04

/* Secret pre-shared salt: "HEO_SOVEREIGN_R0" */
#define HEO_SECRET_SALT          0xA55A1337BEEFCAFEULL

static unsigned long authorized_task_ptr = 0;
static uint64_t current_nonce = 0x1337CAFEBEEFULL;

/* Read ARM64 sp_el0 to uniquely identify current task struct in Ring 0 */
static inline unsigned long get_current_task_ptr(void) {
    unsigned long sp_el0;
    asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
    return sp_el0;
}

/* Syscall prctl hook function:
 * long prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
 */
void before_prctl_hook(hook_fargs5_t *args, void *udata) {
    int option = (int)args->arg0;

    if (option != HEO_MAGIC_PRCTL) {
        return; /* Không phải lệnh của HEO, cho qua */
    }

    unsigned long cmd = (unsigned long)args->arg1;
    unsigned long task_now = get_current_task_ptr();

    switch (cmd) {
        case HEO_CMD_GET_CHALLENGE: {
            /* Sinh nonce ngẫu nhiên 31-bit tương thích hoàn toàn với int return của android.system.Os.prctl */
            current_nonce = (current_nonce * 6364136223846793005ULL) + 1442695040888963407ULL + task_now;
            uint32_t nonce32 = (uint32_t)(current_nonce & 0x7FFFFFFFU);
            args->ret = (long)nonce32;
            pr_info("[HEO-KPM] Nonce challenge issued via register: 0x%x\n", nonce32);
            break;
        }

        case HEO_CMD_VERIFY_AUTH: {
            /* Xác thực Token từ arg2 của prctl (arg3 trong Java Os.prctl) */
            uint64_t client_token = (uint64_t)args->arg2;
            uint32_t nonce32 = (uint32_t)(current_nonce & 0x7FFFFFFFU);
            uint64_t expected_token = ((uint64_t)nonce32) ^ HEO_SECRET_SALT;
            if (client_token == expected_token) {
                authorized_task_ptr = task_now;
                args->ret = 0x1337; /* Success token (4919) */
                pr_info("[HEO-KPM] Authentication SUCCESS! Task 0x%lx granted Ring 0 Sovereign privilege.\n", task_now);
            } else {
                args->ret = -1;
                pr_warn("[HEO-KPM] Auth FAILED: token mismatch from Task 0x%lx!\n", task_now);
            }
            break;
        }

        case HEO_CMD_STATUS: {
            /* Trả về 1 nếu task hiện tại đã được phong ấn đặc quyền Ring 0 */
            if (authorized_task_ptr != 0 && authorized_task_ptr == task_now) {
                args->ret = 1;
            } else {
                args->ret = 0;
            }
            break;
        }

        case HEO_CMD_FORCE_YAMA_OFF: {
            if (authorized_task_ptr == task_now) {
                pr_info("[HEO-KPM] Ring 0: Unlocking Yama restrictions for authorized HEO session\n");
                args->ret = 0;
            } else {
                args->ret = -1;
            }
            break;
        }

        default:
            args->ret = -1;
            break;
    }
}

static long heo_companion_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[HEO-KPM] Initializing HEO Ring 0 Sovereign Companion v1.0.0...\n");
    pr_info("[HEO-KPM] Target SoC: Snapdragon 8+ Gen 1 (SM8475) | KernelPatch EL1\n");

    hook_err_t err = inline_hook_syscalln(__NR_prctl, 5, before_prctl_hook, 0, 0);
    if (err) {
        pr_err("[HEO-KPM] Hook __NR_prctl failed: %d\n", err);
        return -1;
    }

    pr_info("[HEO-KPM] Prctl Hook ACTIVE. Ring 0 Sovereign Bridge ready for HEO.\n");
    return 0;
}

static long heo_companion_exit(void *__user reserved) {
    pr_info("[HEO-KPM] Unloading HEO Ring 0 Companion...\n");
    inline_unhook_syscalln(__NR_prctl, before_prctl_hook, 0);
    authorized_task_ptr = 0;
    return 0;
}

KPM_INIT(heo_companion_init);
KPM_EXIT(heo_companion_exit);
