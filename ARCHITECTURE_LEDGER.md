# ARCHITECTURE LEDGER — TEMPLAR KERNEL & KPM ARSENAL (Xiaomi 12S / SM8475)

## 1. System Overview
- **Target Device**: Xiaomi 12S (`mayfly`, Snapdragon 8+ Gen 1, SM8475)
- **Active Kernel**: Linux 5.10.264-Templar-6.4-Pure-APatch-ZSTD
- **Root Infrastructure**: KernelPatch / APatch (Ring 0 EL1 Execution)
- **Toolchain**: Clang 14 (`clang-14 --target=aarch64-linux-gnu`) + LLD 14 (`aarch64-linux-gnu-ld`)
- **Compilation Flags**: `-O2 -fno-pic -fno-pie -fno-common -mcmodel=small -fno-stack-protector -mgeneral-regs-only -ffreestanding -fno-asynchronous-unwind-tables -fno-unwind-tables`
- **Relocation Standard**: 0 GOT entries (No types 311/312), verified via `llvm-readelf-14 -r`

---

## 2. KPM Arsenal Map (7 Modules)

| Module Name | Binary File | Size | Role | Ring 0 Hook Mechanism |
|-------------|-------------|------|------|----------------------|
| **Pseudo-MGLRU Supreme v2.0** | `pseudo-mglru-supreme.kpm` | 9.3 KB | Generational LRU Emulation + VM Locks | `hook_wrap3` on `get_scan_count` (`ffffffd60337d0ac`) |
| **HEO Scheduler TITAN v1.0** | `heo-scheduler-titan.kpm` | 15.7 KB | Dynamic CPU Core Affinity & CFS Sovereign Governor | `hook_wrap4` on `select_task_rq` (`ffffffd6031a0f94`) + `__get_task_comm` |
| **HEO Ring 0 Companion v2.0** | `heo-ring0-companion.kpm` | 6.3 KB | Authenticated Prctl Syscall Bridge | `inline_hook_syscalln` on `__NR_prctl` with secret salt `0xA55A1337BEEFCAFE` |
| **Pixel 11 Spoofer** | `pixel11-camera-safe-spoofer.kpm` | 4.4 KB | Device Model Spoofer (Camera-Safe) | DMI/Property in-memory override |
| **Ring 0 NetShield** | `ring0-netshield-supreme.kpm` | 3.6 KB | TCP BBR / Network Stack Hardening | Sysctl direct lock |
| **SuSFS Stealth Root** | `susfs-stealth-root.kpm` | 3.2 KB | Kernel-level Root Cloaking | VFS path hiding |
| **ZSTD Memory Engine** | `zstd-memory-engine.kpm` | 2.7 KB | ZRAM Compaction Optimizer | VM parameters lock |

---

## 3. Pseudo-MGLRU v2.0 Technical Formula
- **Conflict Avoidance**: Native `CONFIG_LRU_GEN=y` breaks Xiaomi proprietary `millet.ko` and `migt.ko` due to `struct lruvec` layout differences, causing bootloops at the Mi logo.
- **Solution**: Hook `get_scan_count` (static internal function at `ffffffd60337d0ac`). Millet hooks `android_vh_shrink_node_memcgs` (higher level); they never conflict.
- **Hook Logic**:
  - `nr[0]` (Inactive Anon): Boosted by +50% (`nr[0] = anon + (anon >> 1)`) $\rightarrow$ Aggressively compresses cold background heap to ZSTD ZRAM.
  - `nr[3]` (Active File): Shielded by -50% (`nr[3] = file >> 1`) $\rightarrow$ Retains executable code, DEX, and ART cache in RAM, eliminating disk I/O stutters.
- **VM Tunables**:
  - `vm_swappiness = 160`
  - `watermark_scale_factor = 125`
  - `extra_free_kbytes = 102400` (100MB)
  - `watermark_boost_factor = 0`

---

## 4. HEO Scheduler TITAN v1.0 Technical Formula
- **Purpose**: Overrides EAS (Energy Aware Scheduling). Enforces core affinity based on user sovereignty rather than battery conservation.
- **Hardware Layout**:
  - CPUs 0-3: Cortex-A510 (LITTLE, 1.80 GHz)
  - CPUs 4-6: Cortex-A710 (MID, 2.75 GHz)
  - CPU 7: Cortex-X2 (PRIME, 3.20 GHz)
- **CFS Parameters Locked**:
  - `sysctl_sched_latency`: 4,000,000 ns (4ms, default 10ms) $\rightarrow$ 2.5x faster task evaluations.
  - `sysctl_sched_min_granularity`: 750,000 ns (0.75ms, default 2ms) $\rightarrow$ Smoother preemption for render threads.
  - `sysctl_sched_wakeup_granularity`: 1,000,000 ns (1ms, default 2ms) $\rightarrow$ Instant preemption on user touch.
  - `sysctl_sched_migration_cost`: 500,000 ns (0.5ms) $\rightarrow$ Better CPU cache retention.
- **Xiaomi Metis Parameters**:
  - `mi_boost_duration = 300000` (5 minutes)
  - `limit_bgtask_sched = 0` (No throttling of background compute)
- **Task Steering Engine (`select_task_rq` Hook)**:
  - **Class 1 (Bloatware)**: `facebook`, `instagram`, `tiktok`, `miwallpaper`, `earthSuper` $\rightarrow$ Demoted to Core 0, 1, or 2 (`target_cpu % 3`). Prime and Mid cores completely protected.
  - **Class 2 (AI Engine)**: `llama`, `qwen`, `executor` $\rightarrow$ Pinned to Mid cores 4, 5, or 6 (`4 + (target_cpu % 3)`) for sustained 2.75 GHz throughput without thermal throttle.
  - **Class 3 (Master & UI)**: `myapplication`, `heo`, `surfaceflinger`, `RenderThread`, `composer-service` $\rightarrow$ Elevated to Core 7 (Cortex-X2) if assigned to LITTLE cores.

---

## 5. Storage Deployment Locations on Xiaomi 12S
1. `/data/adb/kpm/`:
   - All 7 `.kpm` binaries reside here for APatch Manager autoloading on boot.
2. `/sdcard/Download/`:
   - `pseudo-mglru-supreme.kpm`
   - `heo-scheduler-titan.kpm`
   - `kpm-arsenal-kernel5.10-SM8475.zip`
3. `/sdcard/Download/KPM_Arsenal_Kernel5.10/`:
   - Contains all 7 standalone `.kpm` modules and the complete ZIP archive.
