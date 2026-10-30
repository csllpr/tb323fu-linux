# Security Audit

**Audit date:** 2026-10-30  
**Audited commit:** `79bcf30`  
**Scope:** OS installation, partitioning and flashing, privileged helper/D-Bus interfaces, update mechanisms, root filesystem builders, and related supply-chain controls.

## Executive summary

Under the security standards appropriate for an OS installer, **the repository should not yet be released as a production installer**. The audit identified **2 high-severity, 3 medium-severity, and 4 low-severity findings**.

No Critical issue was confirmed that would allow an unprivileged local user to gain root privileges directly or bypass the existing flashing hash checks. However, the authenticity guarantees of the installation and update supply chain are insufficient.

The review was performed without modifying the audited source tree. The working tree remained clean.

## High severity

### 1. SteamOS and Armada install unverified plugins downloaded over plaintext HTTP

**Evidence:**

- `tools/install/distros/steamos.sh:25-28`
- `tools/install/distros/armada.sh:25-28`

Both modules download `Packages.gz` and the `swh-plugins` Debian package over HTTP, then extract the package with `dpkg-deb -x` without verifying a signature or a pinned SHA-256 digest. The plugins are subsequently copied into the target system:

- `rootfs/steamos/build-rootfs.sh:237-240`
- `rootfs/armada/build-rootfs.sh:228-232`

**Impact:** An attacker able to intercept the installation network can replace both the package index and the package, place malicious code in the installed image, and have that code executed when PipeWire loads the plugin. This breaks the integrity of the installed OS and its software trust chain.

**Recommended remediation:**

- At minimum, use HTTPS and verify the `.deb` against a pinned SHA-256 digest before extraction.
- Prefer validating the package through Ubuntu's signed `Release` and `Packages` metadata chain instead of downloading an unauthenticated standalone file.
- Disable these two installation modules until verification is implemented.

**Remediation progress (2026-10-30):** Partially addressed. The package-index and `.deb` URLs in both installer modules now use HTTPS. The Ubuntu server returned `200 OK` for the HTTPS package index and the `swh-plugins_0.4.17-3build1_arm64.deb` package, and `bash -n` passed for both modified modules. This finding remains open because the package is still extracted without signature or pinned SHA-256 verification.

### 2. Kernel, helper, and Mesa updates lack a mandatory independent signature root of trust

**Evidence:**

- Initial installer checksum validation: `tools/install/install.sh:512-520`
- The installer explicitly documents that the checksums are not signatures: `tools/install/install.sh:624`
- Signature enforcement is disabled by default: `helper/crates/tb323fu-helper-core/src/config.rs:216-225`
- No project public key is built in: `helper/crates/tb323fu-helper-core/src/kernel.rs:71-77`

`SHA256SUMS` and the kernel, helper, and Mesa assets all come from the same GitHub Release. The checksums detect corruption but cannot establish that a Release is authentic. Minisign support exists, but it is optional and no project key is trusted by default.

**Impact:** Compromise of the GitHub account, release process, or publishing credentials would allow an attacker to distribute a malicious kernel or root helper through the normal installation and update channels. During initial installation, a malicious `.deb` would also execute maintainer scripts in a root chroot on the build host, so the impact is not limited to the tablet.

This is a **documented design risk**, not a bypass of the checksum implementation. It remains high severity for an OS installer.

**Recommended remediation:**

- Use the existing minisign mechanism, ship the project public key, and require valid signatures by default. Unsigned or incorrectly signed releases must be rejected.
- Apply the same trust root in the initial `tools/install/install.sh` path, not only in subsequent helper updates.
- Sign the release metadata and all assets, and add rollback protection and metadata expiration.
- Keep the signing private key offline and separate from GitHub publishing credentials.

## Medium severity

### 3. Several polkit policies grant more privilege than their documentation states

**Evidence:** `helper/data/io.github.joonhoekim.opendevicehelper.policy`

| Action | Actual policy | Documented or commented expectation |
|---|---|---|
| `thermal-performance` | `allow_active=yes` at line 72 | Lines 67-68 say authentication is required |
| `emergency-key-disable` | `allow_active=yes` at line 102 | `helper/README.md:85` says authentication is required |
| `kernel-channel` | `allow_active=yes` at line 186 | Lines 135-137 and `helper/README.md:85-87` say authentication is required |

These actions are used by the corresponding privileged operations:

- `helper/crates/tb323fu-helperd/src/ifaces.rs:914-925`
- `helper/crates/tb323fu-helperd/src/ifaces.rs:1224-1287`
- `helper/crates/tb323fu-helperd/src/kernel.rs:796-816`

**Impact:** Any process in an active local session can, without an administrator password, disable the emergency way back to Android, select the hotter thermal profile or disable panel heat protection, switch to the testing update channel, and change update-check settings.

**Recommended remediation:** Use `auth_admin_keep` for these actions. Consider requiring `auth_admin` every time the emergency recovery mechanism is disabled. Add policy-file tests so that authorization behavior cannot silently diverge from the documented contract.

### 4. Diagnostic export exposes root-only logs and stores them with broad read permissions

**Evidence:**

- Active users require no authentication: `helper/data/io.github.joonhoekim.opendevicehelper.policy:105-109`
- The root daemon performs the export: `helper/crates/tb323fu-helperd/src/ifaces.rs:953-956`
- The archive includes the previous boot journal and kernel log: `helper/crates/tb323fu-helperd/src/diag.rs:141-143`
- The resulting archive is mode `0644`: `helper/crates/tb323fu-helperd/src/diag.rs:158`

The sanitizer covers MAC addresses, IPv4 addresses, the device serial number, hostname, and local usernames (`diag.rs:85-115`). Logs may still contain SSIDs, filesystem paths, other users' activity, or sensitive arguments accidentally logged by programs.

**Impact:** An ordinary active user can use the root D-Bus service to obtain logs that would normally be inaccessible to that user. The `0644` archive may also be readable by other local users.

**Recommended remediation:** Create archives with mode `0600` and make them available only to the requesting user, or return a restricted file descriptor. Clearly disclose the exported data and require confirmation. Prefer an allowlist of safe diagnostic fields over a small denylist of sensitive strings.

### 5. The SteamOS image grants unrestricted passwordless sudo

**Evidence:** `rootfs/steamos/build-rootfs.sh:295-299` writes:

```text
steamos ALL=(ALL) NOPASSWD: ALL
```

**Impact:** Any process running as `steamos` can immediately become root without authentication. Compromise of a browser, game, or other user-space process therefore becomes a full system compromise. The module's experimental status does not make this a safe default installation.

**Recommended remediation:** Remove unrestricted `NOPASSWD`. Use a narrowly scoped command allowlist, polkit, or a dedicated controlled interface for the specific brightness operation that requires elevated privileges.

## Low severity

### 1. Arch packaging uses an unpinned source and is not reproducible

`packaging/arch/PKGBUILD:13-14` obtains source from the repository's default Git branch and sets `sha256sums=(SKIP)`, while the package version remains fixed at `0.4.3`.

**Recommendation:** Pin the source with `#commit=<full commit hash>` or use an authenticated, signed release tag.

### 2. The Fedora builder downloads a mutable Steam archive without content verification

`rootfs/fedora/build-rootfs.sh:388-389` downloads `steam_latest.tar.gz` and extracts it without a pinned hash or signature. HTTPS protects against ordinary network interception but does not provide reproducibility or protection against origin compromise.

**Recommendation:** Pin the artifact version and verify its digest before extraction.

### 3. Unauthenticated D-Bus calls can trigger root filesystem mounts

`helper/crates/tb323fu-helperd/src/ifaces.rs:1060-1068,1121-1134` exposes Roots and Rescan without a polkit check, while scanning causes the root daemon to mount candidate root filesystems.

**Impact:** Any local user can repeatedly trigger privileged mount operations, creating a denial-of-service vector and unnecessary exposure of the kernel's filesystem attack surface.

**Recommendation:** Authorize and rate-limit these operations, and avoid implicit mounts during property reads.

### 4. Website CI actions are not pinned to immutable commits

`.github/workflows/pages.yml:29-57` uses movable action version tags while the workflow has Pages and OIDC permissions. This is outside the OS installation path but remains a supply-chain weakness.

**Recommendation:** Pin every action to a full commit SHA.

## Positive security controls

The review also confirmed several sound controls:

- The Android image in `boot_b` is checked before flashing, with recovery attempted after a failed write: `tools/install/install.sh:908-924`.
- Rust kernel flashing requires unique `boot_a` and `boot_b` devices of equal size, flushes writes, and verifies the data read back: `helper/crates/tb323fu-helper-core/src/kernel.rs:696-706,738-763`.
- Helper updates use path allowlists, tar-entry type checks, per-file hash verification, and rejection of symlink targets.
- The download service uses `DynamicUser`, an isolated writable cache, an empty capability set, and multiple systemd sandbox restrictions.
- Local kernel installation receives a caller-opened file descriptor and accepts only regular files up to 128 MiB, avoiding arbitrary path opens by the root daemon.

## Verification performed

The following checks passed:

- Initramfs tests: **90/90**
- Android state-root and kernel-trial tests: **15/15**
- Kernel-confirmation tests: **21/21**
- `bash -n` over all repository Shell scripts
- Python AST parsing of 9 Python files
- Final `git status` confirmed a clean working tree

## Audit limitations

- Rust unit tests and D-Bus integration tests were not run because the available WSL environment did not contain a Rust toolchain.
- `shellcheck` and `cargo-audit` were not installed, so ShellCheck analysis and third-party dependency vulnerability scanning were not performed.
- No physical-device testing was performed for ADB, SD-card partitioning, or `boot_a` / `boot_b` flashing.

The conclusions therefore derive from source review and the existing offline tests listed above. They do not constitute end-to-end hardware security validation, and they do not establish that third-party dependencies are free of known vulnerabilities.

## Recommended release priorities

1. Block the unauthenticated HTTP downloads and require verified packages.
2. Make offline-signature verification mandatory across initial installation and every update channel.
3. Correct the polkit rules and add authorization regression tests.
4. Remove unrestricted passwordless sudo and restrict diagnostic archive access.
5. Pin remaining source artifacts, restrict privileged mount triggers, and complete Rust, dependency, and physical-device testing before release.
