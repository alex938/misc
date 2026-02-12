# Android Course Notes

> Single source of truth: everything goes in this file (`android.md`). Designed to render cleanly on GitHub.

## Contents
- [0. ADB Quick Reference](#0-adb-quick-reference)
- [1. Platform Overview](#1-platform-overview)
- [2. Security Model](#2-security-model)
- [3. Boot & Init System](#3-boot--init-system)
- [4. Android Runtime](#4-android-runtime)
- [5. Inter-Process Communication](#5-inter-process-communication)
- [6. Development & Debugging Tools](#6-development--debugging-tools)
- [7. Exercises (hands-on)](#7-exercises-hands-on)

## Conventions
- **Host vs device**
  - Commands starting with `adb ...` run on your computer (host).
  - Commands shown without `adb` are intended to run inside `adb shell`.
- `adb shell "..."`: everything inside quotes runs on the device.
- Code fences
  - `bash` = commands
  - `powershell` = Windows host commands
  - `text` = sample output / formats
- References: use bullets with a short title + link (or a plain URL).
- When we add a new topic, we’ll use this structure:
  - Goal
  - Notes
  - ADB commands to try
  - Mini-exercises
  - Takeaways + follow-ups

## 0. ADB Quick Reference
- `adb shell` runs a command on the device from your computer.
- If you are already inside `adb shell`, you can drop the `adb shell` prefix.

### Connect + sanity checks
```bash
adb devices
adb shell id
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.version.release
```

### Run a one-off command / pipeline
```bash
adb shell getprop ro.product.model
adb shell "ps -ef | grep zygote"
```

### Simple app/UI automation (over adb)
```bash
# Get screen size (useful for tap/swipe coordinates)
adb shell wm size

# Launch an app (simple)
adb shell monkey -p com.google.android.youtube 1

# Key events
adb shell input keyevent KEYCODE_HOME
adb shell input keyevent KEYCODE_BACK
adb shell input keyevent KEYCODE_APP_SWITCH

# Touch gestures
adb shell input tap 500 1600
adb shell input swipe 500 1600 500 300 300

# Text input (spaces are usually %s)
adb shell input text hello%sworld
```

### Run as root (if available)
```bash
adb shell su -c "id"
adb shell su -c "ls -l /data/system_ce/0/snapshots"
```

### Copy files
```bash
adb pull /data/local/tmp/capture.png
adb push local_file /data/local/tmp/
```

### Logs
#### PowerShell (Windows)
```powershell
adb logcat -b all
adb logcat -d | Select-String -Pattern 'avc: denied'
```

#### Bash (macOS/Linux/Git Bash)
```bash
adb logcat -b all
adb logcat -d | grep -i "avc: denied"
```

Notes:
- Quoting/pipes run on the device shell when wrapped in `adb shell "..."`.
- For binary files (PNGs/APKs), prefer `adb pull` over streaming output on some Windows shells.

## 1. Platform Overview

### Android as a Platform
- **Android is a platform, not an OS**
- Built on top of the Linux kernel
- Provides a complete software stack for mobile devices

### Android Architecture (high-level stack)

![Android Architecture diagram](android-architecture.png)

> Tip: save the diagram image as `android-architecture.png` in the same folder as this `android.md` file to render it.

#### Layers (bottom → top)
- **Hardware**: the physical device (CPU, GPU, radios, sensors, storage)
- **Linux kernel**: drivers + scheduling/memory + IPC primitives + security (SELinux hooks)
- **Bionic**: Android’s C runtime + dynamic linker (`linker`/`linker64`) used by native code
- **Native libraries**: C/C++ libs used by the framework and apps (media, crypto, graphics, etc.)
- **HAL (Hardware Abstraction Layer)**: vendor/OEM interface layer for hardware features (implemented by vendor components)
- **Android Runtime**:
  - Older diagrams show **Dalvik VM**; modern Android uses **ART**
  - Runs Java/Kotlin bytecode (DEX), provides GC, JIT/AOT, etc.
- **Framework**: Java/Kotlin APIs + system services (ActivityManager, PackageManager, etc.)
- **Applications**: system apps + user apps

#### Bionic (`libc.so`) location (runtime APEX)
- **Bionic** is Android’s C standard library/runtime used by native code (roughly: “Android’s libc”).
  - It implements functions declared in headers like `stdlib.h`, `stdio.h`, etc.
- On many modern Android versions, core runtime pieces ship in the **runtime APEX** (`com.android.runtime`).
  - That’s why `/system/lib*/libc.so` is often a **symlink** into `/apex/com.android.runtime/...`.

Example:
```bash
ls -al /system/lib64/libc.so
# /system/lib64/libc.so -> /apex/com.android.runtime/lib64/bionic/libc.so
```

Related paths (device/version-dependent):
- 64-bit libc: `/apex/com.android.runtime/lib64/bionic/libc.so`
- 32-bit libc (if supported): `/apex/com.android.runtime/lib/bionic/libc.so`
- Dynamic linker binaries are typically `linker` / `linker64` (often also provided by the runtime APEX).

#### Bootstrap Bionic libs (`/system/lib64/bootstrap`)
- On many devices you’ll find a minimal copy of core Bionic libraries under:
  - `/system/lib64/bootstrap/` (and sometimes `/system/lib/bootstrap/`)
- This is used by **early-boot** components that need to run *before* APEX packages are activated/mounted.
  - Idea: avoid a chicken-and-egg problem where an APEX manager would need libraries that live inside APEX.
- So: Bionic isn’t “implemented as an APEX” — it’s **packaged/shipped** via the runtime APEX, but a bootstrap copy may exist on `/system` for early boot.

Example:
```bash
ls -al /system/lib64/bootstrap
# libc.so, libdl.so, libdl_android.so, libm.so, ...
```

Useful checks (over adb):
```bash
adb shell ls -al /system/lib64/libc.so
adb shell readlink /system/lib64/libc.so
adb shell ls -al /system/lib64/bootstrap 2>/dev/null
adb shell ls -al /system/bin/bootstrap 2>/dev/null

# What libc is this process actually mapping?
adb shell 'cat /proc/$$/maps | grep libc.so | head'
```

Notes:
- Many `/system` files show placeholder timestamps like `2009-01-01`; don’t treat them as real “file created” dates.

#### Native code paths
- **JNI (Java Native Interface)**: lets framework/app code call into native (`.so`) libraries.
- **Native (ELF) binaries**: native daemons/tools in userspace that talk to the kernel via syscalls.

#### Typical “app → hardware” flow (common pattern)
- App → Framework API → Binder IPC → system service → HAL → kernel driver → hardware

### Exploit impact by layer (what breaks what)
- When someone says an exploit is “in AOSP” vs “vendor” vs “kernel”, they usually mean **who owns the code** and **how broadly it ships**.

#### AOSP (Android Open Source Project)
- **What it is:** The core open-source Android platform maintained by Google.
  - Framework APIs, system services, core apps, build system, etc.
- **Impact scope:** Potentially **very broad** across many Android devices.
  - In practice, impact depends on Android version, whether OEMs modified/backported the code, and device configuration.
- **Who fixes/ships:** Google publishes patches; OEMs integrate into OTAs; some pieces ship via Mainline.

#### “AOSP external” (third‑party components in AOSP)
- **What it is:** Upstream open-source projects that Android includes (often under an `external/` folder in source).
  - Examples: media/codec libs, TLS/crypto libs, XML parsers, etc. (varies by Android version).
- **Impact scope:** Can be **broad** in Android, and sometimes also affects **non-Android** software if it’s a common upstream library.
- **Note:** You wrote “ASOP external” — if you meant something else by ASOP, tell me and I’ll adjust.

#### Platform vs BSP (Board Support Package)
- **Platform (Android platform layer)**
  - **What it is:** The “OS/platform” side (AOSP framework + system services + system components).
  - **Impact scope:** Broad across devices running that platform code.
- **BSP (Board Support Package)**
  - **What it is:** Device/SoC enablement package (kernel tree + device drivers + bootloader pieces + vendor HAL glue).
  - Usually provided by the SoC vendor/OEM.
  - **Impact scope:** Broad for devices that share that **SoC/board family**, but not necessarily all Android.

#### Vendor / ODM
- **Vendor (`/vendor`)**
  - **What it is:** Hardware/SOC vendor implementation details: HALs, vendor services, blobs, configs.
  - **Impact scope:** Devices using that vendor stack (often many models share the same SoC vendor code).
- **ODM (`/odm`)**
  - **What it is:** Board-variant overlays/customizations on top of vendor.
  - **Impact scope:** Usually **narrower**, tied to a specific device family/variant.

#### Carrier
- **What it is:** Carrier-specific apps/configuration/overlays (APNs, carrier config, provisioning, custom services).
- **Impact scope:** Typically **limited** to devices sold/configured for that carrier (or devices where that carrier package is present).

#### Linux kernel
- **What it is:** The core kernel underneath Android.
- **Impact scope:** Potentially very broad, but **not literally “all Linux”**.
  - A kernel CVE affects the Linux versions/configs that include the vulnerable code.
  - Android devices often run heavily customized kernels, so scope depends on version + vendor patches.

### Android Versions & API Levels
- **API Level**: Integer value that uniquely identifies the framework API revision
- **Android Version**: User-facing version name (e.g., Android 14)
- Apps declare minimum API level in their manifest (`minSdkVersion`)
- Higher API levels add new features and deprecate old ones

### App Manifest (`AndroidManifest.xml`)
- Required XML file that describes essential info about your app to the **build tools**, the **Android OS**, and **Google Play**.
- Think “app metadata” (similar in spirit to **.NET manifests** and Darwin/Apple **`Info.plist`** files).
- It’s a particular XML grammar (fixed element/attribute keywords) covering:
  - **Generic metadata**: app name/label, icon, title, theme, etc.
  - **Software & hardware requirements / compatibility**:
    - `<uses-sdk>` (`minSdkVersion`, `targetSdkVersion`) — often configured via Gradle, but the manifest concept is the same.
    - `<uses-feature>` for required/optional device features.
  - **Security requirements**:
    - `<uses-permission>`: permissions your app requests.
    - `<permission>`: permissions your app defines (to protect your own components/APIs).
  - **Application components**:
    - `<activity>`, `<service>`, `<receiver>`, `<provider>`
    - plus `<intent-filter>` entries describing how components can be started.

Minimal structure:
```xml
<manifest>
  <application>
    <activity />
    <service />
    <receiver />
    <provider />
  </application>
</manifest>
```

#### Intent filters: deep links vs “allowed network domains”
- `<intent-filter>` describes which **incoming Intents** a component (usually an `<activity>`) can handle.
- For web links, intent-filters are used for **deep links** / **Android App Links**.
- Important correction: intent-filters do **not** define what domains your app can “query/connect to” on the network.
  - Outbound network access is primarily controlled by:
    - `android.permission.INTERNET`
    - `android:usesCleartextTraffic` / Network Security Config (cleartext + trust settings)
    - SELinux / firewall rules / enterprise policies (device-dependent)
  - If you meant “what apps can my app *query* via PackageManager?” that’s **package visibility** (Android 11+), controlled by the manifest `<queries>` section.

##### Typical deep link intent-filter
```xml
<intent-filter android:autoVerify="true">
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />

  <data android:scheme="https" android:host="example.com" />
</intent-filter>
```

Notes:
- `android:autoVerify="true"` relates to **Android App Links**:
  - Android will try to **verify** the association between the app and the web domain.
  - Verification requires a Digital Asset Links file on the website (commonly `https://<host>/.well-known/assetlinks.json`).
  - Verification is **per host** (if you list both `example.com` and `www.example.com`, you need assetlinks on both).
  - App Links verification is for **https**; `http` links are treated as regular (unverified) deep links.
  - Even when verified, users can still change “Open supported links” behavior in Settings.
- Each `<data .../>` element is an alternative match.
  - If you want both `example.com` and `www.example.com`, include both:

```xml
<data android:scheme="https" android:host="example.com" />
<data android:scheme="https" android:host="www.example.com" />
```

Useful commands (test link handling):
```bash
# Fire a VIEW intent for a URL
adb shell am start -W \
  -a android.intent.action.VIEW \
  -c android.intent.category.BROWSABLE \
  -c android.intent.category.DEFAULT \
  -d "https://example.com/"

# Inspect a package for intent filters / domains (best-effort; output varies by version)
adb shell "dumpsys package com.example.app | grep -i -E 'autoVerify|intent|domain|host'"

# Discover available app-links commands on your device (names vary by version)
adb shell "pm help | grep -i link"
adb shell "cmd package help 2>/dev/null | grep -i link"
```

### Permissions (Android framework permission model)
- It’s common to say “Android permissions” (not really “Dalvik permissions”).
  - Dalvik/ART executes your code.
  - Permission enforcement typically happens in **framework system services** (over Binder) and sometimes in the **kernel** (SELinux/DAC/network restrictions).
- Permissions are **named strings** like:
  - platform: `android.permission.*`
  - app-defined/vendor: `com.google.*`, `com.example.*`

#### Declaring vs requesting
- **Requesting permissions** (what your app wants):
  - `<uses-permission android:name="..." />`
- **Defining permissions** (what your app provides/protects):
  - `<permission android:name="..." ... />`

#### Protection levels (high level)
- `normal`: granted at install (low-risk)
- `dangerous`: requires **runtime** user consent (Android 6.0+; behavior depends on `targetSdkVersion`)
- `signature` / `privileged`: only granted to apps signed with the right key and/or installed in privileged locations (system/priv-app)

#### Internal: numeric protection flags (`packages.xml` / `protection=`)
- Internally, Android stores a permission’s protection level as an **int bitfield** (`PermissionInfo.protectionLevel`).
- In `/data/system/packages.xml`, you may see permissions with an attribute like `protection="1218"`.
- That number is typically:
  - a **base** protection (`normal`=0, `dangerous`=1, `signature`=2)
  - OR’d with **flags** (e.g., `privileged`, `appop`, `pre23`, `preinstalled`, etc.).

Common numeric examples:
- `0` = normal
- `1` = dangerous
- `2` = signature
- `18` = signature|privileged (`0x12` = `0x2` + `0x10`)

Example: `android.permission.WRITE_SETTINGS`
- You may see `protection=1218`.
- Decode:
  - `1218` (dec) = `0x4C2` (hex)
  - `0x2` = signature (base)
  - `0x40` = appop flag (permission is gated/tracked by AppOps)
  - `0x80` = pre23 flag (legacy/compat behavior for apps targeting < 23)
  - `0x400` = preinstalled flag (affects how preinstalled/system apps are treated)

Practical meaning:
- `WRITE_SETTINGS` is a **special app access** permission (AppOps-backed).
- For regular apps, you typically need the user to grant it via Settings:
  - check: `Settings.System.canWrite(context)`
  - send user to: `ACTION_MANAGE_WRITE_SETTINGS`

Useful commands (over adb; root likely required for `packages.xml`):
```bash
# Find the permission entry in packages.xml
adb shell su -c "grep -n 'android.permission.WRITE_SETTINGS' /data/system/packages.xml | head"

# Show protection attributes around permissions (host-side filtering)
adb shell su -c "cat /data/system/packages.xml" | grep -A 2 -B 2 'protection=' | head -40

# Same idea, but run grep/head on-device (no host grep/head required)
adb shell su -c "grep -A 2 -B 2 'protection=' /data/system/packages.xml | head -40"

# Open the special-access Settings screen for a package
adb shell am start -a android.settings.action.MANAGE_WRITE_SETTINGS -d package:com.example.app

# Check AppOps state (device-dependent; may require privileges)
adb shell cmd appops get com.example.app WRITE_SETTINGS 2>/dev/null || adb shell appops get com.example.app WRITE_SETTINGS
```

#### Inspect permissions (device or over adb)
```bash
# From host (adb):
adb shell pm list permissions
adb shell dumpsys package com.example.app

# If you’re already in `adb shell`:
# pm list permissions
# dumpsys package com.example.app
```

Example output (`pm list permissions`):
```text
All Permissions:

permission:android.permission.MANAGE_APPOPS
permission:android.permission.WRITE_SETTINGS
permission:com.android.permission.INSTALL_EXISTING_PACKAGES
...
```

### App install locations (`/data/app`, `base.apk`, splits)

#### Where APKs live
- **User-installed apps** typically live under:
  - `/data/app/...`
- **Preinstalled/system apps** typically live under:
  - `/system/app/...`
  - `/system/priv-app/...` (privileged system apps)

#### Modern `/data/app` directory names (`~~...`)
- On modern Android (notably Android 11+), the `/data/app` layout often looks like:

```text
/data/app/~~<random>/
  <packageName>-<random>/
    base.apk
    base.dm
    split_config.*.apk   (optional)
    lib/
    oat/
```

- The `~~...` and `-<random>` parts are **randomized/obfuscated directory names**.
  - This makes it harder to infer installed apps by guessing paths (ties into **package visibility** restrictions).
  - The real “source path” is tracked by PackageManager.

#### What the files/dirs mean
- `base.apk`: the main APK (base split)
- `split_config.*.apk`: split APKs (common with Play App Bundles)
  - Examples: ABI split (`arm64_v8a`), language split (`en`), density split (`xxhdpi`)
- `base.dm` (and `split*.dm`): **Dex metadata**
  - Optional metadata installed alongside APKs
  - Used for install-time optimizations / profile-guided compilation
  - Passed to `dex2oat` (ART compiler) during dexopt
- `lib/`: extracted native libraries (when extraction is enabled/needed)
  - Even when not extracted, native libs can also be loaded directly from inside the APK
- `oat/`: compiled ART artifacts (device/OS dependent)
  - often includes `.odex` / `.vdex` for faster startup

#### Practical commands
```bash
# From host (adb):
adb shell pm path com.google.android.videos

# Show more package info (paths, splits, etc.) (runs grep on-device)
adb shell "dumpsys package com.google.android.videos | grep -E 'codePath|resourcePath|split'"

# List all package → APK path mappings
adb shell "pm list packages -f | head"

# Pull the base APK once you have its path (example path from pm path)
adb pull /data/app/~~.../com.example-.../base.apk

# Inspect installed directory contents (root required on most devices)
adb shell "ls -l /data/app/~~*/com.google.android.videos-*/"
adb shell "ls -l /data/app/~~*/com.google.android.videos-*/oat 2>/dev/null"

# If you’re already in `adb shell`, you can drop the `adb shell` prefix.
```

#### APK is a ZIP: compression methods (`Stored`) + zipalign
- An APK is a **ZIP** archive. Each entry can be:
  - **Stored** (uncompressed, ZIP method 0)
  - **Deflated** (compressed, ZIP method 8)

##### What `Stored` means in `unzip -v`
- In output like:

```bash
unzip -v -l app.apk
```

- The **“Stored”** column is the ZIP **compression method**.
  - `Stored` = bytes are included *as-is* (no decompression step when reading them)
  - the “compressed size” equals the “uncompressed size”

##### Why Android keeps some entries uncompressed
- Performance: stored entries can often be accessed via **`mmap(2)`** directly from the APK without decompression.
- Memory: mapped pages can sometimes be **shared** instead of copied.
- Tradeoff: increases APK size.

Common examples of entries that may be stored:
- `classes*.dex` (DEX bytecode)
- native libs: `lib/<abi>/*.so`
- ART profiles: `assets/dexopt/baseline.prof`, `assets/dexopt/baseline.profm`
- sometimes resource blobs like `resources.arsc` (depends on build/tooling)

##### zipalign (alignment for faster mmap)
- **zipalign** adds padding so that **stored (uncompressed)** entries start at a chosen alignment.
- The “classic” alignment is **4 bytes** (good for many resource reads).
- With `zipalign -p`, shared libraries (`.so`) are **page-aligned** (typically **4096 bytes**), which is better for mapping.

Key idea (your note):
- If a stored file begins at a page boundary inside the ZIP, the runtime can map it more directly from the initial ZIP mapping (fewer copies).

##### Commands
```bash
# Inspect which entries are stored/deflated
unzip -v -l app.apk | head

# Check alignment (4-byte)
zipalign -c -v 4 app.apk

# Align (run BEFORE signing)
zipalign -p -f -v 4 input.apk output.apk

# Verify signatures after (re)signing
apksigner verify --verbose output.apk
```

Notes:
- **zipalign must be done before signing** (otherwise signatures break).
- “page alignment” matters most for stored `.so` / `.dex` style direct mapping.

#### META-INF in APKs + APK signing schemes (v1–v4)

##### What `META-INF/` is (in APKs)
- APKs are ZIPs, and `META-INF/` is a standard place for ZIP/JAR metadata.
- In APKs, `META-INF/` can contain:
  - **v1 (JAR) signing artifacts** (e.g. `MANIFEST.MF`, `*.SF`, `*.RSA`)
  - **Java/Kotlin ServiceLoader files** under `META-INF/services/*` (not related to signing)

> Note: `META-INF/MANIFEST.MF` is a **JAR manifest** (not Android’s `AndroidManifest.xml`).

##### v1 (JAR signing / “META-INF signature”)
- **Where:** `META-INF/MANIFEST.MF`, `META-INF/*.SF`, `META-INF/*.(RSA|DSA|EC)`
- **What it signs:** digests of individual ZIP entries (legacy approach)
- **Why it still exists:** compatibility with older Android versions / tooling

Typical files:
- `META-INF/MANIFEST.MF`: list of entries + hashes
- `META-INF/<name>.SF`: hashes over `MANIFEST.MF` sections
- `META-INF/<name>.RSA`: PKCS#7 signature block + cert chain

##### v2 (APK Signature Scheme v2)
- **Where:** in the **APK Signing Block** (not in `META-INF/`)
- **What it signs:** the APK as a whole (stronger protection than v1)

##### v3 (APK Signature Scheme v3)
- **Where:** also in the **APK Signing Block**
- **Adds:** **signing key rotation** support (signing lineage / proof-of-rotation)

##### v3.1 (APK Signature Scheme v3.1)
- **Where:** APK Signing Block (new block ID)
- **Why it exists:** improves v3 rotation behavior by allowing **SDK version targeting** for the rotated signer.
  - Android 13+ can use the rotated signer in the v3.1 block
  - older Android versions ignore v3.1 and use the original signer from v3

##### v4 (APK Signature Scheme v4)
- **Where:** separate file next to the APK: `*.apk.idsig`
- **Purpose:** streaming/incremental install verification (Merkle tree over APK bytes)
- **Important:** v4 requires a complementary **v2 or v3** signature in the APK.

##### Useful commands
```bash
# Show META-INF entries
unzip -l app.apk 'META-INF/*'

# Print which signature schemes are present + certs
apksigner verify --verbose --print-certs app.apk

# If you have a v4 file, verify it too
apksigner verify --verbose --v4-signature-file app.apk.idsig app.apk 2>/dev/null
```

#### Dumping resources from an APK (aapt / aapt2)
- `aapt` (Android Asset Packaging Tool) can **dump compiled resources** from an APK.
- Helpful when you’re reversing/triaging and you have:
  - resource IDs like `0x7f0a0123`
  - you want to see resource **types** (`layout`, `string`, `id`, `drawable`, …), config variants (`en`, `xxhdpi`, night, …), and values

##### Resource table dump
```bash
# Dump the compiled resource table (from resources.arsc) to a file (output can be huge)
aapt d resources "app.apk" > resources_dump.txt

# Equivalent spelling
aapt dump resources "app.apk" > resources_dump.txt
```

##### Other useful dumps
```bash
# Package name, version, SDK, features, permissions, launchable activity, etc.
aapt dump badging app.apk

# Permissions only
aapt dump permissions app.apk

# Dump compiled (binary) XML structure (useful for AndroidManifest.xml)
aapt dump xmltree app.apk AndroidManifest.xml

# aapt2 variants (newer build-tools)
aapt2 dump resources app.apk
aapt2 dump xmltree app.apk AndroidManifest.xml
```

##### Where `aapt` lives (Android SDK build-tools)
- In the Android SDK: `<SDK>/build-tools/<version>/aapt(.exe)` and `aapt2(.exe)`.
- Use a full path, or add the build-tools directory to `PATH`.

#### Current Android Versions & API Levels

| Android Version | API Level | Code Name | Release Year |
|----------------|-----------|-----------|-------------|
| Android 15 | 35 | Vanilla Ice Cream | 2024 |
| Android 14 | 34 | Upside Down Cake | 2023 |
| Android 13 | 33 | Tiramisu | 2022 |
| Android 12L | 32 | Snow Cone v2 | 2022 |
| Android 12 | 31 | Snow Cone | 2021 |
| Android 11 | 30 | Red Velvet Cake | 2020 |
| Android 10 | 29 | Quince Tart | 2019 |
| Android 9 | 28 | Pie | 2018 |
| Android 8.1 | 27 | Oreo | 2017 |
| Android 8.0 | 26 | Oreo | 2017 |
| Android 7.1 | 25 | Nougat | 2016 |
| Android 7.0 | 24 | Nougat | 2016 |
| Android 6.0 | 23 | Marshmallow | 2015 |
| Android 5.1 | 22 | Lollipop | 2015 |
| Android 5.0 | 21 | Lollipop | 2014 |

#### Notable API Level Changes
- **API 21+**: ART becomes default (Lollipop)
- **API 23+**: Runtime permissions model (Marshmallow)
- **API 26+**: Background execution limits (Oreo)
- **API 28+**: TLS 1.2 required by default (Pie)
- **API 29+**: Scoped storage introduced (Android 10)
- **API 30+**: Package visibility restrictions (Android 11)
- **API 33+**: May drop 32-bit support on some devices (Android 13)

#### “Most used” Android versions (AppBrain sample)
- AppBrain publishes a device OS distribution based on **devices running the AppBrain SDK**.
- **Last updated: February 10, 2026** (data window: last 7 days).
- For **February 2026**, AppBrain reports the most popular Android OS version is:
  - **Android 15 (API 35): 20.8% market share**
- Note: this is **not** the official Google Play distribution; it reflects AppBrain’s SDK user sample.
- Page: AppBrain → Android Statistics → Top Android OS versions (has a CSV download button on the page)

### System Updates & Modular System Components

#### Project Mainline
- Introduced in **Android 10**.
- Goal: make parts of the OS **updatable as packages** (often called **Google Play system updates** on Google-certified devices).
- Modularizes key components so they can be updated **independently of a full OTA**.
- Updates are designed to be **atomic** (install/rollback as a unit) and to use **stable interfaces**.

#### APEX (Android Pony EXpress)
- **APEX = Android Pony EXpress**.
- A package/container format used by Mainline for low-level components that must be available **early in boot**.
- Common behavior:
  - Preinstalled APEX packages live under `/system/apex/`
  - Updated/staged APEX packages live under `/data/apex/`
  - Mounted read-only under `/apex/<name>@<version>/` and often bind-mounted at `/apex/<name>/`
  - Managed by the `apexd` daemon very early in the boot process

##### Useful commands (Mainline / APEX)
```bash
# See mounted APEX modules
ls /apex

# See preinstalled APEX packages
ls /system/apex

# See updated/staged APEX packages (if any)
ls /data/apex 2>/dev/null

# Check apexd status
getprop init.svc.apexd
ps -ef | grep apexd

# List APEX packages (availability varies by Android version/build)
cmd package list packages --apex-only
pm list packages --apex-only

# APEX often shows up as loop-mounted images
mount | grep -E ' /apex/|loop'
df | grep apex
```

#### Bionic (Android libc)
- **Bionic** is Android’s C runtime:
  - `libc` (C standard library)
  - `libm` (math)
  - `libdl` (dynamic loading)
  - **dynamic linker** (`linker`/`linker64`)
- It plays the same “role” as **glibc** on many Linux distros, but it’s Android-specific.
- Used by:
  - the entire Android userspace (native services/daemons)
  - NDK apps (native code)

##### Why it shows up under APEX
- On modern Android, core runtime pieces (including Bionic) are shipped in the **`com.android.runtime` APEX**.
- That’s why you may see:
  - `/system/lib64/libc.so` → symlink into `/apex/com.android.runtime/.../bionic/libc.so`

##### Useful commands
```bash
# See where libc is coming from
ls -l /system/lib64/libc.so 2>/dev/null

# Explore the runtime APEX
ls -l /apex/com.android.runtime 2>/dev/null
ls -l /apex/com.android.runtime/lib64/bionic 2>/dev/null

# Dynamic linker locations (varies by device)
ls -l /system/bin/linker* 2>/dev/null
```

#### Linker configuration (`/linkerconfig`, `ld.config.txt`)
- `/linkerconfig` is typically a **tmpfs** mount that contains **generated linker configuration**.
- It exists largely because of **APEX**: the dynamic linker needs a consistent way to find and restrict libraries across `/system`, `/vendor`, and mounted APEX modules.

##### What `ld.config.txt` tells you
- `ld.config.txt` is the Bionic linker’s config file that defines **linker namespaces** (library-loading sandboxes), including:
  - which directories are searched for `.so` files (**search paths**)
  - which directories are allowed at all (**permitted paths**)
  - which namespaces can “link” to others and which **shared libs** can cross boundaries
- It is a big part of:
  - **Treble separation** (platform vs vendor libs)
  - **APEX runtime wiring** (core libraries coming from `/apex/...`)
  - reducing “accidental” or unsafe library loading

##### Quick inspection commands
```bash
# Confirm it's tmpfs and list its contents
df /linkerconfig
ls -F /linkerconfig

# Read the config
cat /linkerconfig/ld.config.txt | head -n 80

# Look for key parts
grep -n "^\[" /linkerconfig/ld.config.txt | head              # section headers
grep -n "^namespace\." /linkerconfig/ld.config.txt | head     # namespace definitions
grep -n "search\.paths" /linkerconfig/ld.config.txt | head
grep -n "permitted\.paths" /linkerconfig/ld.config.txt | head
```

Notes:
- “**linker namespace**” here is **not** the same thing as a Linux namespace (mount/net/etc.).
- The per-APEX directories you see under `/linkerconfig/` are used for APEX-related linker config/state.

### Build Fingerprint
- **Unique identifier** for a specific Android build
- Retrieved with: `getprop ro.build.fingerprint`
- Used for identifying device configuration, troubleshooting, and compatibility

#### Fingerprint Format
```text
brand/product/device:version/build_id/build_number:build_type/build_keys
```

#### Example Breakdown
```text
google/flame/flame:11/RQ1A.201205.008/6943376:user/release-keys
```

| Section | Value | Meaning |
|---------|-------|----------|
| **Brand** | `google` | Manufacturer/brand name |
| **Product** | `flame` | Product name (marketing name) |
| **Device** | `flame` | Device codename (Pixel 4) |
| **Version** | `11` | Android version number |
| **Build ID** | `RQ1A.201205.008` | Build identifier (date-based) |
| **Build Number** | `6943376` | Incremental build number |
| **Build Type** | `user` | Build variant (user/userdebug/eng) |
| **Build Keys** | `release-keys` | Signing keys used |

#### Build Types
- **user**: Production build for end users (optimized, limited debugging)
- **userdebug**: Debug build with root access available (for developers)
- **eng**: Engineering build (maximum debugging, not secure)

#### Build Keys
- **release-keys**: Official release, signed with manufacturer's private keys
- **test-keys**: Test build, signed with publicly available test keys
- **dev-keys**: Development build keys

### Security Patch Level
- **Monthly security updates** from Google
- Critical for device security and vulnerability fixes
- Format: `YYYY-MM-DD`

#### Checking Security Patch
```bash
getprop | grep -i patch
```

#### Example Output
```text
[ro.build.version.security_patch]: [2020-12-05]
[ro.vendor.build.security_patch]: [2020-12-05]
```

#### Key Properties
- **`ro.build.version.security_patch`**: System security patch level
- **`ro.vendor.build.security_patch`**: Vendor/hardware security patch level
- Both should be updated together for full security coverage
- Google releases patches on the first Monday of each month
- Older patch dates indicate potential security vulnerabilities

### SDK Version Properties
- Shows the API level of the device and supported SDK versions
- Retrieved with: `getprop | grep -i sdk`

#### Example Output
```bash
[ro.build.version.sdk]: [30]
[ro.build.version.min_supported_target_sdk]: [23]
[ro.build.version.preview_sdk]: [0]
[ro.build.version.preview_sdk_fingerprint]: [REL]
[ro.product.build.version.sdk]: [30]
[ro.system.build.version.sdk]: [30]
[ro.system_ext.build.version.sdk]: [30]
[ro.vendor.build.version.sdk]: [30]
```

#### Key SDK Properties

| Property | Example | Meaning |
|----------|---------|----------|
| `ro.build.version.sdk` | `30` | Current API level (Android 11) |
| `ro.build.version.min_supported_target_sdk` | `23` | Minimum target SDK for apps (Marshmallow) |
| `ro.build.version.preview_sdk` | `0` | Preview SDK version (0 = stable release) |
| `ro.build.version.preview_sdk_fingerprint` | `REL` | Release status (REL = stable, not preview) |
| `ro.product.build.version.sdk` | `30` | Product partition SDK level |
| `ro.system.build.version.sdk` | `30` | System partition SDK level |
| `ro.system_ext.build.version.sdk` | `30` | System extension partition SDK level |
| `ro.vendor.build.version.sdk` | `30` | Vendor partition SDK level |

#### Notes
- All partition SDK levels should typically match
- `min_supported_target_sdk` prevents very old apps from running
- Preview SDK values > 0 indicate a beta/preview Android version

### Core Components

#### Linux Kernel Services
- Process management
- Memory management
- Device drivers
- Security features
- Power management

#### Binary Format: ELF (Executable and Linkable Format)
- Standard binary format for executables and libraries
- Used for native code and system binaries
- Supports dynamic linking

#### Pseudo Filesystems
- **`/proc`**: Process information and kernel parameters
- **`/sys`**: Kernel and device information (sysfs)
- **`/dev`**: Device files for hardware access

### Supported Architectures
- **Primary**: `arm64` (64-bit ARM)
- **Other architectures**:
  - `x86`: 32-bit Intel/AMD
  - `x86_64`: 64-bit Intel/AMD
  - `armv6`: ARM v6 (legacy)
  - `armv7`: ARM v7 (32-bit)
  - `armv8`: ARM v8 (64-bit, same as arm64)
  - `mips`: MIPS architecture (legacy)
  - `ppc`: PowerPC (rare)

### ARM Architecture Details

#### ARMv8 / AArch64
- **Generic 64-bit ARM architecture**
- Most devices use ARMv8 with sub-features
- Sub-versions: ARMv8.1 through ARMv8.9

##### Important ARMv8 Versions
- **ARMv8.1**: Enhanced virtualization, atomic operations
- **ARMv8.3**: Pointer authentication, complex number support
- **ARMv8.5**: Memory tagging, random number generation
- **Security implications**: Later versions include hardware security features

#### ARMv9
- **ARMv9.0 through ARMv9.6**
- **ARMv9.0**: Aligns with ARMv8.5 features as baseline
- **Actively developed line** (ARMv8.x is now deprecated)
- Focus on AI/ML, security, and performance improvements
- SVE2 (Scalable Vector Extension 2) for better performance

#### CPU Features Detection
```bash
cat /proc/cpuinfo | grep Features
```

##### Common CPU Features
- **half**: Half-precision floating point
- **thumb**: Thumb instruction set (16-bit)
- **fastmult**: Fast multiplication
- **vfp/vfpv3/vfpv4**: Vector Floating Point (different versions)
- **edsp**: Enhanced DSP instructions
- **neon**: SIMD (Single Instruction Multiple Data) extension
- **tls**: Thread Local Storage support
- **idiva/idivt**: Integer division (ARM/Thumb)
- **lpae**: Large Physical Address Extension (>4GB RAM)
- **evtstrm**: Event stream for WFE (Wait For Event)
- **aes**: AES encryption acceleration
- **pmull**: Polynomial multiply long (for crypto)
- **sha1/sha2**: SHA hashing acceleration
- **crc32**: CRC32 checksum acceleration

---

## 2. Security Model

### SELinux / SEAndroid
- **SEAndroid**: Android's implementation of SELinux (Security-Enhanced Linux)
- Introduced in **Android 5.0 (Lollipop)**
- Mandatory Access Control (MAC) system for enhanced security

#### SEAndroid = SELinux + Android Extensions
- **Core**: Exactly the same SELinux as standard Linux
- **Extensions**: Minor additions for Android-specific features
  - System properties access control
  - Binder service security policies
- At filesystem level, identical to SELinux

### DAC vs MAC

#### DAC (Discretionary Access Control)
- Traditional Unix permissions (chmod/chown/chgrp)
- Owner-based access control
- User/Group/Other permissions (rwx)
- Controlled by file owner

#### MAC (Mandatory Access Control)
- SELinux policy-based access
- System-wide security policies
- Cannot be overridden by file owner
- More granular and secure than DAC

#### DAC and MAC Can Disagree
- Both systems must allow access for operation to succeed
- DAC may permit, but MAC can still deny
- Example: File shows `rw-rw-rw-` (DAC allows all), but SELinux policy blocks access

#### Example: Binder Device Files
```bash
ls -al /dev/*binder
```
```text
crw-rw-rw- 1 root root 10, 53 1970-06-27 11:37 /dev/binder
crw-rw-rw- 1 root root 10, 52 1970-06-27 11:37 /dev/hwbinder
crw-rw-rw- 1 root root 10, 51 1970-06-27 11:37 /dev/vndbinder
```

- **DAC permissions**: `rw-rw-rw-` (everyone can read/write)
- **Reality**: Access still denied by SELinux

```bash
cat /dev/vndbinder
# Permission denied
```

#### Binder Device Types
- **`/dev/binder`**: General-purpose Binder for framework services
- **`/dev/hwbinder`**: Hardware Binder for HAL (Hardware Abstraction Layer)
- **`/dev/vndbinder`**: Vendor Binder for vendor-to-vendor communication

### SELinux Policy Files

#### CIL (Common Intermediate Language)
- SELinux policies are written in CIL format
- Human-readable intermediate language for SELinux policies
- Compiled and loaded into the kernel at boot time

#### Policy File Locations
```bash
ls /etc/selinux
```
```text
mapping/
plat_file_contexts
plat_hwservice_contexts
plat_mac_permissions.xml
plat_property_contexts
plat_seapp_contexts
plat_sepolicy.cil
plat_sepolicy_and_mapping.sha256
plat_service_contexts
```

#### Key Policy Files

| File | Purpose |
|------|----------|
| `plat_sepolicy.cil` | Main platform SELinux policy (CIL format) |
| `plat_file_contexts` | File security contexts (labels for files) |
| `plat_property_contexts` | System property security contexts |
| `plat_service_contexts` | Binder service security contexts |
| `plat_hwservice_contexts` | Hardware service (HAL) security contexts |
| `plat_seapp_contexts` | App security contexts and domains |
| `plat_mac_permissions.xml` | MAC permissions for app signing |
| `mapping/` | Version mapping for policy compatibility |
| `plat_sepolicy_and_mapping.sha256` | Integrity checksum |

#### Property Contexts (`*property_contexts`)
- Property context files map **Android system properties** (names/prefixes) → **SELinux property labels** (types).
- They exist across multiple partitions ("svop" = **system/vendor/odm/product**), for example:
  - `/system/etc/selinux/plat_property_contexts`
  - `/vendor/etc/selinux/vendor_property_contexts` (if present)
  - `/odm/etc/selinux/odm_property_contexts` (if present)
  - `/product/etc/selinux/product_property_contexts` (if present)
  - `/system_ext/etc/selinux/system_ext_property_contexts` (if present)

##### Why they matter
- When a process runs `setprop ...`, Android determines the property’s **label** using these files.
- SELinux policy rules in the compiled policy (`*.cil` → compiled policy) decide whether the process domain is allowed to **set/get** that labeled property.
- Implementation detail: properties are served via **shared memory** (`/dev/__properties__`), but **writes** are mediated by the property service (typically via `/dev/socket/property_service`).
- In practice, **everything must agree**:
  - property name matches a context entry → correct label
  - `.cil` policy includes allow rules for that label
  - otherwise you’ll see denials (often `avc: denied`) even if DAC permissions look open.

##### Common property namespaces
- `ro.*`: read-only properties (generally not settable after early boot)
- `persist.*`: persisted across reboots (written under `/data/`)
- `vendor.*`, `odm.*`, `product.*`, `system_ext.*`: partition/vendor-specific properties

##### Useful commands
```bash
# Inspect property context mappings
ls /system/etc/selinux/*property*contexts 2>/dev/null
ls /vendor/etc/selinux/*property*contexts 2>/dev/null
ls /odm/etc/selinux/*property*contexts 2>/dev/null
ls /product/etc/selinux/*property*contexts 2>/dev/null

# Look up how a property name is labeled
grep -n "^persist\." /system/etc/selinux/plat_property_contexts | head

# Read/set properties
getprop ro.build.fingerprint
setprop persist.sys.example 1

# If a setprop fails, look for SELinux denials
logcat -b all | grep -i "avc: denied"
```

#### Vendor vs ODM CIL Files
- **Platform** (`/system/etc/selinux`): Google's base Android policy
- **Vendor** (`/vendor/etc/selinux`): Device manufacturer additions
- **ODM** (`/odm/etc/selinux`): ODM-specific policy additions
- Policies are **layered**: Platform → Vendor → ODM
- Each layer can extend but not remove base policies

#### Policy Compilation
```bash
ls /system/bin/secilc
```
- **`secilc`**: SELinux CIL Compiler
- Compiles CIL policy files into binary format
- Binary policy is loaded into the kernel at boot
- Happens during init process startup

#### Dumping the Active (Loaded) SELinux Policy
- The **currently loaded** (compiled) SELinux policy is exposed at:
  - `/sys/fs/selinux/policy`
- This is a **binary policy**, not the original `.cil` sources.

##### Common workflow (device → host)
1) On device: copy it somewhere convenient (often `/data/local/tmp/`)
```bash
cat /sys/fs/selinux/policy > /data/local/tmp/policy
```
2) On host: pull it with adb
```bash
adb pull /data/local/tmp/policy
```
3) Optional cleanup
```bash
rm /data/local/tmp/policy
```

##### Important note: where `adb` runs
- `adb` is a **host-side tool**.
- If you run `adb pull ...` *inside* an Android shell (`adb shell`), you’ll typically get something like:
  - `/system/bin/sh: adb: inaccessible or not found`

#### Checking Current SELinux Status
```bash
getenforce                         # Enforcing / Permissive / Disabled
cat /sys/fs/selinux/enforce        # 1=enforcing, 0=permissive (if SELinux enabled)

# (root) toggle enforcement
setenforce 0                       # Permissive
setenforce 1                       # Enforcing

# Alternative (same effect as setenforce)
echo 0 > /sys/fs/selinux/enforce   # Permissive
echo 1 > /sys/fs/selinux/enforce   # Enforcing

# Contexts (labels)
ps -Z                              # Show SELinux label column (process context)
ps -eZ | grep <process>            # Filter a process by name
ls -Z /path/to/file                # Show file SELinux context
id -Z                              # Show current shell/user SELinux context

# View SELinux denials (device-dependent)
logcat -b all | grep -i avc
```

##### Understanding `ps -Z` labels
- Typical Android format: `u:r:<domain>:s0` (may include categories like `s0:c123,c456`)
  - `u` = SELinux user
  - `r` = SELinux role
  - `<domain>` = SELinux type/domain for the process (the most important part)
  - `s0` = MLS/MCS security level
- Example:
  - `u:r:magisk:s0` → process running in the **magisk** SELinux domain
  - Seeing `magisk` usually indicates a **rooted / modified** (non-production) device setup.

##### “echo 0” vs “disabled SELinux”
- `echo 0 > /sys/fs/selinux/enforce` sets SELinux to **Permissive** (policy still loaded, just not enforced).
- Fully **disabled** SELinux is rare on modern Android and typically requires boot-time/kernel changes.

#### SELinux Modes
- **Enforcing**: SELinux policy is enforced; forbidden actions are blocked
- **Permissive**: Violations are logged but not blocked (debugging mode)
- **Disabled**: SELinux is off (rare in modern Android)

### seccomp-bpf (syscall filtering)
- **seccomp** is a Linux kernel feature to restrict what **syscalls** a process can make.
- **seccomp-bpf** = seccomp “filter” mode where a **BPF program** decides which syscalls/arguments are allowed.
- Android uses seccomp-bpf as part of its sandboxing (wider adoption across the platform by Android 8.0+).

#### “BPF” here = Berkeley Packet Filter lineage
- **BPF originally** came from the *Berkeley Packet Filter* concept used for packet capture/filtering.
- In **seccomp-bpf**, that same BPF instruction set idea is reused to filter **syscalls**, not packets.

#### Who applies it on Android (Bionic / Zygote)
- The enforcement is **in the kernel**.
- On Android, the filter is typically **installed from userspace** by core components (e.g., Zygote) using libc helpers.
  - In practice, you’ll often see this described as “**Bionic applies/installs seccomp**” because Android’s libc and core runtime code are involved in loading policies and calling into the kernel.

#### How it relates to SELinux
- **SELinux (MAC)**: controls access to kernel objects (files, sockets, binder services, properties, etc.) based on labels.
- **seccomp**: controls *which syscalls you’re allowed to invoke* (even if SELinux would otherwise permit the operation).
- In practice, **both** can block you:
  - SELinux deny → `avc: denied ...`
  - seccomp deny → often a kill/`SIGSYS`/`EPERM`/`EACCES` (depends on filter action)

#### BPF vs netfilter/iptables (don’t mix them up)
- **netfilter/iptables**: kernel firewall framework (packet filtering/NAT)
- **BPF**: programmable filtering/instrumentation framework
  - wasn’t “abandoned”; it evolved (classic BPF → **eBPF**) and is widely used for networking + tracing

#### Policy location (common)
```bash
ls /system/etc/seccomp_policy 2>/dev/null
ls /vendor/etc/seccomp_policy 2>/dev/null
```
- Policies can be shipped for different components/services.

#### Check if a process has seccomp enabled
```bash
PID=<pid>
cat /proc/$PID/status | grep -E 'Name|Uid|Seccomp'
```
- `Seccomp: 0` = off
- `Seccomp: 2` = filter mode (most common)

### eBPF (extended BPF) notes
- **eBPF** is the modern, much more powerful evolution of BPF.
- Used for networking, observability, and security tooling (tracepoints/kprobes/cgroup hooks, etc.).
- It’s **not** “complete kernel control” by default:
  - programs are **verified** and run in a constrained VM
  - loading/attaching eBPF is typically restricted (capabilities / SELinux / kernel config)
- Root often has *more* ability to use eBPF, but what’s possible depends on device policy and kernel build.

Useful checks (device-dependent):
```bash
# Is BPF fs mounted?
mount | grep bpf
ls -ld /sys/fs/bpf 2>/dev/null

# If bpftool exists (often not on user builds)
which bpftool 2>/dev/null && bpftool prog show
```

### Android AIDs (`AID_*`) (Android IDs: well-known UIDs/GIDs)
- Android defines a set of **fixed numeric user/group IDs** for core system components and privileged access groups.
- These IDs show up as process UIDs/GIDs, file ownership, and supplemental groups.
- Source of truth in AOSP: `android_filesystem_config.h` (commonly referenced from `system/core/libcutils/...`).

Why they matter:
- **Privilege separation**: key daemons/services don’t run as root; they run as specific AIDs.
- **DAC permissions**: file/device-node ownership + mode bits often rely on these group IDs (e.g., access to audio/camera/log devices).

Examples (from `android_filesystem_config.h`):
```c
#define AID_ROOT 0      /* traditional unix root user */
#define AID_SYSTEM 1000 /* system server */
#define AID_RADIO 1001  /* telephony subsystem, RIL */
#define AID_INPUT 1004  /* input devices */
#define AID_ADB 1011    /* android debug bridge (adbd) */
#define AID_MEDIA 1013  /* mediaserver process */

#define AID_HSM 1064    /* hardware security module subsystem */

#define AID_INET 3003      /* can create IP sockets */
#define AID_NET_RAW 3004   /* can create raw sockets */
#define AID_NET_ADMIN 3005 /* can configure interfaces and routing tables */
```

Example: device-node access controlled by an AID group
```bash
# /dev entry owned by user+group "hsm" (character device)
ls -l /dev | grep hsm
# crw-rw---- 1 hsm hsm 502,   0 ... citadel0

# Show numeric owner/group IDs (maps to the AID numbers)
ls -ln /dev/citadel0
```
- Here, the `hsm` group (AID_HSM) + mode bits `crw-rw----` mean only the `hsm` user/group can read/write that device node.

Example: input device nodes + `shell` group membership
```bash
ls -l /dev | grep input
# drwxr-xr-x 2 root root  ... input
# crw-rw---- 1 root input ... v4l-touch28

id
# uid=2000(shell) gid=2000(shell) groups=...,1004(input),...
```
- If a device node is `root:input` with mode bits like `crw-rw----`, then any process that’s a member of the `input` group (AID_INPUT=1004) can read/write it via **DAC**.
- Note: **SELinux still applies** (DAC group membership alone doesn’t guarantee access on all devices/builds).

Example: `inet` group and opening network sockets
```bash
id
# uid=2000(shell) gid=2000(shell) groups=...,3003(inet),...
```
- On many Android kernels with **paranoid network** enabled, a process needs to be in `inet` (AID_INET=3003) (or related net groups like `net_raw`/`net_admin`) to create **AF_INET/AF_INET6** sockets.
  - Without it, `socket(AF_INET, ...)` can fail with `EACCES`.
- On kernels without paranoid network, normal Linux rules apply (no special group needed to create TCP/UDP sockets), but Android may still restrict networking via other mechanisms (SELinux, firewall rules, etc.).

Quick checks (device):
```bash
# Show your current UID/GID + groups (often printed with AID names)
id

# Show numeric Uid/Gid for a process
PID=<pid>
cat /proc/$PID/status | grep -E '^Uid|^Gid'

# See numeric owners/groups for files
a ls -ln /path 2>/dev/null || ls -ln /path
```

### Package list (`/data/system/packages.list`) (PackageManager)
- Plain-text, whitespace-delimited list of installed packages with **UIDs**, **data dirs**, **SELinux seinfo**, and **supplemental GIDs**.
- Used by system components to map package → identity/dirs.
- Treat as **read-only**:
  - manual edits are typically **overwritten/regenerated** (often on boot or when packages change)
  - if it disagrees with PackageManager’s internal state, the system will prefer the authoritative state and rebuild derived files
- **Format can vary by Android version/OEM**, but a common modern layout is **8 columns**:

```text
<packageName> <uid> <debuggable> <dataDir> <seinfo> <gids> <profileable> <longVersionCode>
```

Column meanings (common):
1) `packageName`
- e.g. `com.google.android.youtube`

2) `uid`
- The app’s Linux UID.
- For user 0, this is often the **appId** (e.g. `10203`). For other users it may be offset by `userId * 100000`.

3) `debuggable`
- `0` / `1` indicating whether the package is debuggable.

4) `dataDir`
- Where the app’s data lives for that user.
- You’ll commonly see:
  - `/data/user/0/<pkg>` = CE (credential-encrypted) user data
  - `/data/user_de/0/<pkg>` = DE (device-encrypted) user data

5) `seinfo`
- String used by SELinux app labeling (feeds into `seapp_contexts`).
- Often looks like: `default:targetSdkVersion=30` or `platform:privapp:targetSdkVersion=28`.

6) `gids`
- Supplemental group IDs assigned to the app (comma-separated), or `none`.
- Example: `3003` (inet) or `3002,3003,3007,...`

7) `profileable`
- `0` / `1` indicating whether the app is profileable by shell (often `0`).

8) `longVersionCode`
- The package version code (can be a large integer).

Example line:
```text
com.google.android.youtube 10203 0 /data/user/0/com.google.android.youtube googlepulse:targetSdkVersion=30 3003 0 1521343936
```

Useful commands (over adb; may require root):
```bash
# view the file
adb shell su -c "head -n 20 /data/system/packages.list"

# find one package
adb shell su -c "grep '^com.google.android.youtube ' /data/system/packages.list"

# cross-check: UID + version from PackageManager
adb shell "pm list packages -U | grep com.google.android.youtube"
adb shell "dumpsys package com.google.android.youtube | grep -E 'userId=|versionCode|seinfo|gids'"

# show CE/DE data dirs
adb shell ls -ld /data/user/0/com.google.android.youtube 2>/dev/null
adb shell ls -ld /data/user_de/0/com.google.android.youtube 2>/dev/null
```

Mini exercise:
- Pick 2–3 packages, locate their lines, and confirm:
  - UID matches `pm list packages -U`
  - `dataDir` exists
  - `gids` explain any extra access (e.g., `3003(inet)`)

Related ranges (very common):
- **Apps** get per-app UIDs (commonly starting at `10000` for user 0).
- **Isolated processes** often use UIDs in the `99xxx` range (you’ll see names like `u0_i*`).

### Isolated processes / “isolated apps”
- Android’s sandbox is strongly based on **UID separation**.
- Some processes run as **isolated UIDs** (commonly in the `99xxx` range for user 0).
  - This is often what people mean by “AID 9XXXXX”.
- These processes are typically **heavily restricted**:
  - different (tighter) SELinux domain (often `isolated_app`)
  - little/no filesystem access to normal app private data
  - fewer privileges/capabilities

#### Why isolated processes exist
- Run risky components (renderers, media, parsers, etc.) with minimal privileges.
- Real-world examples: Chrome/WebView renderer processes, media components, etc.

##### Opt-in: `android:isolatedProcess="true"` (Manifest)
- You can opt-in to an **isolated service** by setting `android:isolatedProcess="true"` on a `<service>` in `AndroidManifest.xml`.
- The system runs that service in a **separate isolated process** with a **unique isolated UID** (`u0_i*`).
- Key implications:
  - Does **not** run under your app’s normal UID → can’t directly access your app’s private files in `/data/data/<pkg>`
  - Does **not** inherit your app’s permissions (treat it like “no-permissions” by default)
  - Communication is typically via **Binder** (the service’s exposed interface)

Example:
```xml
<service
    android:name=".MyIsolatedService"
    android:isolatedProcess="true"
    android:exported="false" />
```

Notes:
- You can also use `android:process=":name"` to control the process name, but isolation is controlled by `isolatedProcess`.
- This is a sandboxing tool; it reduces blast radius if the isolated component is compromised.

#### Identify isolated processes (quick)
```bash
# See SELinux domain + user
ps -Z | grep -i isolated

# Inspect a specific PID’s UID and seccomp state
PID=<pid>
cat /proc/$PID/status | grep -E 'Name|Uid|Gid|Seccomp'
```

#### Example: switching to an isolated UID (debugging)
- You can sometimes emulate “isolated UID restrictions” by switching the shell to an isolated UID (requires root/su).

```bash
su 90001
id
```
Example output:
```text
uid=90001(u0_i1) gid=90001(u0_i1) groups=90001(u0_i1) context=u:r:magisk:s0
```
Notes:
- `u0_i1` indicates an **isolated UID** (user 0, isolated #1).
- Your **SELinux context** may *not* match a real isolated app domain when you do this (e.g. it might still show `magisk`).
  - Some restrictions are **UID-based** (so this still matters)
  - Others are **SELinux-domain-based** (so this may not fully reproduce real app behavior)

##### Sanity check: your processes now run as `u0_i*`
- After switching to an isolated UID, you can confirm your commands are running under that UID via `ps`.

```bash
ps -Zef | grep chrom
```
Example (note: this is just the `grep` process itself):
```text
u:r:magisk:s0   u0_i1   ...  grep chrom
```
Tips:
- If you’re trying to find *Chrome*, filter out the grep line:
  - `ps -Zef | grep -i chrom | grep -v grep`
- Chrome renderer tabs often show up as processes like:
  - `com.android.chrome:sandboxed_process*`
  and may run under **isolated UIDs** (`u0_i*`) with tight restrictions.

#### Binder / ServiceManager restrictions for isolated callers
- Even if you can *list* services, an isolated UID may be refused when trying to **get a service handle** or perform sensitive operations.
- Enforcement can happen in multiple layers:
  - **ServiceManager SELinux checks** (service `find/list/add` permissions via `service_contexts` + policy)
  - **Per-service permission checks** (many services check caller UID/permissions; some explicitly treat isolated UIDs as untrusted)

Useful commands:
```bash
# List Binder services; filter out empty interface brackets (sometimes shown as [])
service list | grep -v '\[\]'

# Quick test: does ServiceManager let you see a specific service?
service check activity

# If something is denied, search logs
logcat -b all | grep -i -E 'avc: denied|servicemanager|binder'
```

### Linux namespaces (mount namespace, net namespace, etc.)
- **Linux namespaces** isolate global system resources per-process (container-style isolation).
- Each namespace type shows up under `/proc/<pid>/ns/` as a symlink like `mnt:[4026534057]`.
  - The number is an internal kernel ID; **same number = same namespace**, different number = different namespace.

#### Common namespace types
- `mnt`: mount namespace (separate mount table / filesystem view)
- `net`: network namespace (interfaces, routing tables, iptables/nftables context)
- `uts`: hostname/domainname (`uname`)
- `pid`: process ID namespace
- `user`: UID/GID namespace (not always used on Android)
- `ipc`: SysV IPC / POSIX message queues
- `cgroup`: cgroup namespace (view of cgroup hierarchy)
- `time`: clock namespace (kernel support varies)

#### Mount namespaces (what they are)
- A **mount namespace** gives a process (and its children) its own view of mounts.
- Mount/unmount/remount operations are isolated to that namespace (unless namespaces are shared).
- This enables things like:
  - different processes seeing different filesystems mounted at the same path
  - “systemless” overlays via bind mounts/overlayfs without changing underlying blocks
  - per-sandbox filesystem views

#### Useful commands
```bash
# See which namespaces your current shell is in
ls -l /proc/$$/ns

# Compare your mount namespace vs init (PID 1)
readlink /proc/$$/ns/mnt
readlink /proc/1/ns/mnt

# See mount tables (different per mount namespace)
cat /proc/$$/mountinfo | head
cat /proc/1/mountinfo | head

# Look for specific mounts
cat /proc/$$/mountinfo | grep -E ' /apex | /linkerconfig | /system '
```

Notes:
- Android uses namespaces in several places, but **UID + SELinux** are still the primary app isolation mechanisms.
- Root tools commonly use **mount namespaces** + bind/overlay mounts to change what specific processes see.

### Example: power of root (Magisk mirror + sensitive config access)
- With root, you can often access files that are normally off-limits to apps and the `shell` user.
- A common real-world example is Wi‑Fi configuration storage.

#### `WifiConfigStore.xml` (com.android.wifi)
- On many modern Android builds, Wi‑Fi is a Mainline module (**`com.android.wifi`**).
- Its state/config can live under **APEX data** directories such as:
  - `/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml`
  - `/data/misc_ce/0/apexdata/com.android.wifi/WifiConfigStore.xml` (CE)
- This file may include sensitive fields (e.g. **`PreSharedKey`** for WPA‑PSK networks). Treat it like a secret.

#### Why you may see `/dev/.../.magisk/mirror/...`
- Magisk often creates a **mirror** tree like:
  - `/dev/<random>/.magisk/mirror/...`
- This is related to Magisk’s **mount-namespace + bind/overlay** setup (“systemless” behavior).
- Tools like `find / ...` may show both the real paths and the mirrored/overlayed paths.

#### Useful commands (safe inspection)
```bash
# Locate Wi‑Fi config store (paths vary by device/version)
find /data -name "WifiConfigStore.xml" 2>/dev/null

# Inspect permissions + SELinux labels (don’t paste the file contents in notes)
ls -lZ /data/misc/apexdata/com.android.wifi/WifiConfigStore.xml 2>/dev/null
ls -lZ /data/misc_ce/0/apexdata/com.android.wifi/WifiConfigStore.xml 2>/dev/null

# Check if Magisk mirror exists
ls -ld /dev/*/.magisk/mirror 2>/dev/null
```

### Linux Device Mapper (dm)
- **Device Mapper (dm)** is a Linux kernel framework that maps one block device to a **virtual** block device.
- The virtual device can be a simple passthrough, or it can apply transformations.

#### Mental model
- Filesystem → **dm virtual block device** → (transform) → real block device
- Read path can also apply transforms/checks on the way back.

#### Why it shows up in Android (notably Android 5.0+)
- **Encryption (dm-crypt)**: map an encrypted block device to a decrypted view
- **Verified Boot / dm-verity**: integrity-checking layer for partitions
- Later Android versions also use dm for things like **logical/dynamic partitions** (e.g., dm-linear on top of `super`).

#### dm-crypt (block encryption / “FDE”)
- **dm-crypt** provides transparent block-device encryption:
  - Encrypts **on write** before data hits the real block device
  - Decrypts **on read** as data returns to the caller
- In Android terminology, **Full-Disk Encryption (FDE)** historically means **`/data` is encrypted** (not literally every partition).

##### Key handling (high-level)
- **Android 5.x era**: FDE was commonly implemented with dm-crypt on `/data`.
  - The `/data` key is protected by the user’s credential (PIN/password) plus device-specific secrets (when hardware-backed).
  - Without the key, `/data` can’t be mounted/decrypted.
- **Android 7.0+**: Android introduced **File-Based Encryption (FBE)** (fscrypt) on many devices.
  - FBE splits keys into:
    - **DE (device-encrypted)**: available at boot for “Direct Boot” data
    - **CE (credential-encrypted)**: only available after the user unlocks
  - Course-simplification mapping: “**7.0 key available from TrustZone**” ≈ DE storage being unlockable at boot; CE still depends on user unlock.

##### Hardware binding (“CPU ↔ flash pairing” idea)
- Keys are often protected/derived in the TEE (**TrustZone / Keymaster**).
- Encrypted userdata is typically **tied to that hardware**; moving the flash/storage chip to a different device usually won’t decrypt it.

##### Gatekeeper (PIN/password verification) and TEE (TrustZone)
- Android’s lockscreen credential verification typically flows through:
  - Keyguard/UI → framework (`system_server`) → `gatekeeperd` → Gatekeeper HAL (`android.hardware.gatekeeper@1.0`) → TEE (TrustZone)
- The “TEE” step is device-specific (Qualcomm QSEE, Trusty, OP-TEE, …).
  - Usually you can observe the **userspace boundary** (Binder/HwBinder + kernel driver calls), but not the secure-world internals on production builds.

###### Interfaces + transaction codes (useful when reading traces)
- Framework Binder service: `android.service.gatekeeper.IGateKeeperService`
  - AIDL method order (so classic Binder transaction codes are often 1..N in that order):
    1) `enroll(...)`
    2) `verify(...)`
    3) `verifyChallenge(...)`
    4) `getSecureUserId(...)`
    5) `clearSecureUserId(...)`
  - So in practice, when you see `IGateKeeperService::3`, it often corresponds to `verifyChallenge(...)`.
- Gatekeeper HAL:
  - HIDL: `android.hardware.gatekeeper@1.0::IGatekeeper` (over `/dev/hwbinder`)
    - Method order: `enroll(...)` (1), `verify(...)` (2), `deleteUser(...)` (3), `deleteAllUsers()` (4).
    - So `IGatekeeper::2` is typically `verify(...)`.
  - AIDL HAL (newer devices/versions): `android.hardware.gatekeeper.IGatekeeper/default`

###### References
- [Gatekeeper architecture overview (AOSP docs)](https://source.android.com/docs/security/features/authentication/gatekeeper)
- [`gatekeeperd` daemon (AOSP source)](https://android.googlesource.com/platform/system/core/+/refs/heads/main/gatekeeperd/gatekeeperd.cpp)
- [`IGateKeeperService.aidl` (frameworks/base, Java)](https://android.googlesource.com/platform/frameworks/base/+/ee699a6/core/java/android/service/gatekeeper/IGateKeeperService.aidl)
  - Note: AOSP documents that the framework AIDL must be kept in sync with the `system/core` binder interface.
- [`IGateKeeperService.aidl` (system/core binder, JS required)](https://cs.android.com/android/platform/superproject/main/+/main:system/core/gatekeeperd/binder/android/service/gatekeeper/IGateKeeperService.aidl)
- [`IGateKeeperService.h` (system/core binder header w/ transaction codes)](https://android.googlesource.com/platform/system/core/+/master/gatekeeperd/IGateKeeperService.h)
- [`IGatekeeper.hal` (HIDL 1.0)](https://android.googlesource.com/platform/hardware/interfaces/+/master/gatekeeper/1.0/IGatekeeper.hal)
- [`IGatekeeper.aidl` (AIDL HAL, JS required)](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/gatekeeper/aidl/android/hardware/gatekeeper/IGatekeeper.aidl)
- [`IGatekeeper.aidl` (AIDL HAL, Gitiles mirror)](https://android.googlesource.com/platform/hardware/interfaces/+/8fc1714797633dbe7fccc82b2cbf0799f6d45b5e/gatekeeper/aidl/android/hardware/gatekeeper/IGatekeeper.aidl)

Security note:
- Gatekeeper `verify*` calls necessarily involve sensitive credential material (the user-provided secret and/or derived handles).
  - Avoid saving raw Parcel/hexdump output to logs or notes.

###### Tracing “PIN entered” from Android userspace
- Identify the Gatekeeper processes:
```bash
ps -ef | grep gatekeeper
```

- Trace Binder between `system_server` and `gatekeeperd` (framework service):
  - Device node: `/dev/binder`
  - Interface token often shows up as **UTF-16** in the Parcel (so you’ll see `00` bytes between ASCII letters in a hex dump).
- Trace HWBinder between `gatekeeperd` and the Gatekeeper HAL:
  - Device node: `/dev/hwbinder`
  - HIDL interface token: `android.hardware.gatekeeper@1.0::IGatekeeper`
  - `IGatekeeper::2` is typically `verify(...)` (credential check).

Example (Pixel `flame`, using `jtrace64`):
```text
BR_TRANSACTION ... from system_server ... Method: android.service.gatekeeper.IGateKeeperService::3(?)
BR_TRANSACTION ... from /system/bin/gatekeeperd ... Method: android.hardware.gatekeeper@1.0::IGatekeeper::2
```

###### Getting closer to the TrustZone boundary
- After the HAL receives `IGatekeeper::verify`, it typically calls into a vendor TEE client library which talks to a kernel driver, e.g.:
  - Qualcomm: `/dev/qseecom` (or other vendor-specific TEE interfaces)
  - Trusty: `/dev/trusty-ipc-dev0`
  - OP-TEE: `/dev/tee0`
- Quick check: what device nodes does the Gatekeeper HAL have open?

```bash
# Example PID discovery; adjust name to match your device
PID=$(pidof android.hardware.gatekeeper@1.0-service-qti 2>/dev/null)
[ -n "$PID" ] && ls -l /proc/$PID/fd 2>/dev/null | grep -i -E 'qsee|trusty|tee|ion|dmabuf'
```

Notes:
- This kind of tracing is great to prove “unlock triggers Gatekeeper verify and then a TEE driver call”, but it won’t decode the credential unless you parse the Binder Parcel or instrument the processes.

##### Useful encryption-related commands
```bash
# Encryption state (varies by Android version/device)
getprop ro.crypto.state
getprop ro.crypto.type

# Check what block device backs /data (and which FS: ext4 vs f2fs)
mount | grep ' /data '

# Look for dm-crypt style mappings
ls -l /dev/block/dm-* 2>/dev/null
```

#### File-Based Encryption (FBE) / fscrypt (Android 7.0+)
- **FBE** = per-directory / per-file encryption (vs whole-block encryption).
- Often described as **directory-based encryption**.
- Implemented via the Linux kernel’s **fscrypt** framework:
  - Historically referred to as **ext4crypt** on ext4 in Android
  - Also supported by **f2fs** (encryption support built in)

##### “Before First Unlock” (BFU) vs “After First Unlock” (AFU)
- **BFU**: device has booted, user has **not** entered their credential yet
  - **CE keys** (credential-encrypted) not available
  - only **DE** (device-encrypted / Direct Boot) storage is accessible
- **AFU**: user has unlocked at least once since boot
  - CE keys become available

##### Direct Boot aware
- **Direct Boot** refers to the period where the device has booted but is still in **BFU**.
- A component marked **directBootAware** can run in BFU and must only touch **DE** storage.
- If a component is *not* Direct Boot aware, it generally won’t run until AFU (and will fail if it tries to access CE data in BFU).

##### DE vs CE: why you see “some data in C(E) and some not”
- On FBE devices, there are effectively two app storage trees:
  - **CE (Credential Encrypted)**: “normal” app data, locked until user unlock
  - **DE (Device Encrypted)**: available at boot (Direct Boot)
- Many apps/services store a small amount of “must work at boot” state in **DE**, while keeping most user/private state in **CE**.

##### Android broadcasts (BFU vs AFU)
- `android.intent.action.LOCKED_BOOT_COMPLETED`: sent in BFU to Direct Boot aware components
- `android.intent.action.BOOT_COMPLETED`: sent after unlock (AFU)

##### Choosing DE vs CE (developer view)
- Default app storage is typically **CE**.
- To use **DE** storage:
  - Mark components that must run BFU with `android:directBootAware="true"`.
  - Use **Device Protected Storage** APIs (e.g., create a device-protected context) so files/DB/SharedPrefs land under `user_de`.
  - Optional manifest default: `android:defaultToDeviceProtectedStorage="true"` (use with care; not all data should be in DE).

##### Useful BFU/AFU checks (shell)
```bash
# Is the user “credential unlocked” yet? (varies by build)
getprop sys.user.0.ce_available

# Compare CE vs DE app directories (root needed on most production builds)
ls -ld /data/data /data/user/0 /data/user_de/0
readlink /data/data

# Look at a specific package’s dirs
PKG=com.example.app
ls -ld /data/user/0/$PKG /data/user_de/0/$PKG 2>/dev/null

# User state often shows LOCKED vs UNLOCKED
dumpsys user | grep -i -E "unlock|state"
```

##### DE vs CE storage locations (common)
- **DE (device-encrypted)**: available BFU
  - `/data/user_de/0/` (user 0)
  - `/data/system_de/`
- **CE (credential-encrypted)**: available AFU
  - `/data/user/0/` (user 0)
  - `/data/system_ce/`
  - `/data/data/` is commonly a symlink to `/data/user/0` (for user 0)

##### Practical check: is CE available?
```bash
getprop sys.user.0.ce_available
# 0/false = BFU, 1/true = AFU (property/value varies by build)
```

##### Example BFU behavior (why `/data/data` looks “locked”)
- On an FBE device, if you try (with sufficient permissions) to list a **CE** directory before first unlock:
  - file names may appear as gibberish (filename encryption), or
  - operations may fail until CE is available.
- **Note:** on many production builds, the `shell` user can’t access `/data/data` even AFU (DAC/SELinux), so:
  - `Permission denied` ≠ automatically “CE locked”
  - use root or compare with DE locations to separate *permissions* from *encryption state*.

```bash
# (root or appropriate permissions)
ls -ld /data/data /data/user/0 /data/user_de/0
ls /data/user_de/0            # DE (should be accessible BFU)
ls /data/data                 # CE (typically not usable BFU)
```

#### dm-verity (read-only integrity enforcement)
- **dm-verity** is a device-mapper target used to enforce **read-only filesystem integrity**.
- It is commonly used as part of **Android Verified Boot (AVB)**.
- Works mainly on the **read path**:
  - When a block is read, dm-verity checks it against a **precomputed hash tree** (Merkle tree).
  - Only returns the block if the hash matches; otherwise you’ll get an I/O error (or a boot failure depending on mode).
- Because hashes are precomputed, the protected partition is effectively **not writable** (writes would change blocks and fail verification).
- Rough analogy: **APFS volume sealing** (system volume is sealed with a signed hash tree and verified).

##### Hash table / hash tree (how it’s laid out)
- People often say “**hash table**”, but dm-verity uses a **hash tree** stored on disk (sometimes called the hashtree).
- **Leaf level**: each **data block** (e.g., 4 KiB) is hashed (often with a salt).
- Those hashes are packed into **hash blocks**.
- Then **hash blocks are hashed**, producing the next level up.
- Repeat until there’s a single **root hash**.

```text
Data blocks:   D0   D1   D2   D3   ...
Leaf hashes:   h0   h1   h2   h3   ...  where hi = H(salt || Di)
Hash blocks:   HB0  HB1 ...         (each HB contains many h's)
Next level:    H(HB0) H(HB1) ...
...
Root hash:     ROOT
```

##### How a read is verified (step-by-step)
1. App/process reads some file → filesystem needs **data block Di**.
2. Filesystem reads Di through the dm-verity virtual block device.
3. dm-verity finds the **expected hash** for Di inside the hashtree.
   - This requires reading the relevant hash block(s).
4. dm-verity verifies the hash block(s) up to the root (hash blocks are also protected by the tree).
5. dm-verity hashes Di and compares:
   - match → return data
   - mismatch → fail according to policy (EIO/log/panic/etc.)

##### Where the trusted root hash comes from
- The **root hash** (and other parameters like block size + hash algorithm) must come from a **trusted** source.
- On Android with **AVB**, this is typically described in **vbmeta** (signed), and used to set up the dm-verity mapping at boot.

##### Where the hashtree (“hash table”) is stored
- The hashtree is stored as **raw blocks on disk** (not a normal file).
- It’s typically either:
  - **appended to the same partition** that holds the verified filesystem image, or
  - stored on a **separate hash/verity block device/partition**.
- The exact location comes from the **device-mapper verity table** (data device, hash device, hash start offset).

```bash
# Inspect dm tables and look for verity mappings
for t in /sys/block/dm-*/dm/table; do echo "== $t =="; cat "$t"; echo; done | grep -i verity -n
```

##### What happens on mismatch (modes)
- Depending on configuration, a mismatch can:
  - return an **I/O error** (EIO) to the caller
  - **log** and continue (less strict)
  - **panic/reboot** (most strict)

##### What dm-verity prevents (persistent tampering)
- Prevents “edit system files on disk” style attacks on verified partitions (typically `/system`, `/vendor`, etc.).
- Prevents simple remount-and-modify approaches on **locked** devices with verity enforcement.
- Also blocks bypassing the filesystem by writing directly to the underlying block device (the hashes won’t match).

##### What dm-verity does NOT prevent (runtime tricks with root)
- If an attacker has **root**, they can still change what a process *sees* at runtime using Linux features like:
  - **bind mounts**
  - **overlay mounts** (common in “systemless” mods)
  - **mount namespaces** (different processes can see different mount layouts)
- These tricks can be hard to notice without privileged inspection, because they may not modify the underlying verified blocks.

##### Useful commands (dm-verity / verified boot)
```bash
# Verified Boot indicators (property names/values vary across devices)
getprop ro.boot.verifiedbootstate        # commonly: green/yellow/orange/red
getprop ro.boot.vbmeta.device_state      # commonly: locked/unlocked
getprop ro.boot.veritymode               # commonly: enforcing/logging/eio/disabled

# Kernel cmdline often includes verity/AVB-related flags
cat /proc/cmdline | tr ' ' '\n' | grep -i verity

# See what block devices back important mounts
cat /proc/mounts | grep -E ' /system | /vendor | /odm | /product |dm-'

# Compare mount namespaces (root needed to inspect arbitrary processes)
readlink /proc/1/ns/mnt
readlink /proc/self/ns/mnt

# Mount tables (init vs current shell)
cat /proc/1/mountinfo | head
cat /proc/self/mountinfo | head

# DM metadata (works even when dmsetup isn't present)
for f in /sys/block/dm-*/dm/name; do echo "$f: $(cat $f)"; done
for f in /sys/block/dm-*/dm/uuid; do echo "$f: $(cat $f)"; done
```

#### Useful commands (availability depends on build)
```bash
# Look for dm devices
ls -l /dev/block/dm-* 2>/dev/null
ls -l /dev/block/mapper 2>/dev/null
cat /proc/partitions | grep dm-

# See what is mounted from dm devices
cat /proc/mounts | grep dm-

# Verified Boot related boot properties (if present)
getprop ro.boot.verifiedbootstate
getprop ro.boot.vbmeta.device_state
getprop ro.boot.veritymode

# If dmsetup exists (often not on user builds)
dmsetup ls
```

---

## 3. Boot & Init System

### Init System (`/system/etc/init`)
- **init**: The first process started by the kernel during Android boot
- **RC files**: Init configuration files (`.rc` files) that define services, actions, and properties
- Located in `/system/etc/init` directory

#### `init` is PID 1 (Android’s “systemd-like” process)
- On Linux/Android, **PID 1** is special:
  - It’s the ultimate **ancestor** of almost every userspace process.
  - It **adopts orphans** (when a parent dies).
  - It must **reap children** via `wait*()` to prevent zombie accumulation.
- Android `init` also:
  - parses `.rc` files and starts/stops services
  - runs core boot logic (mounts, permissions, SELinux setup, etc.)
  - hosts the **property service** (system properties)

Useful checks:
```bash
cat /proc/1/cmdline | tr '\0' ' '
cat /proc/1/status | head
```

#### Init RC files across partitions (`[svop]/etc/init/*.rc`)
- It’s not just `/system/etc/init/*.rc`; modern devices load init configs from multiple partitions:
  - `/system/etc/init/*.rc`
  - `/vendor/etc/init/*.rc`
  - `/odm/etc/init/*.rc`
  - `/product/etc/init/*.rc`
  - `/system_ext/etc/init/*.rc` (if present)
- `.rc` files can also `import` other `.rc` files (common for vendor/hw bring-up).

```bash
ls -d /system/etc/init /vendor/etc/init /odm/etc/init /product/etc/init /system_ext/etc/init 2>/dev/null
grep -R "^import " /system/etc/init 2>/dev/null | head
```

#### `/dev/socket/*`: Unix domain sockets (common daemon IPC)
- Android uses many Unix domain sockets under `/dev/socket/` for daemon-to-daemon IPC.
- Compared to Binder, sockets can be a simpler/lower-overhead fit for some **system daemons** and **early-boot** components.
  - Apps generally don’t talk to these directly (SELinux + privilege separation); apps primarily use **Binder** and framework APIs.
- DAC permissions often show intended clients:
  - e.g. sockets owned by group `inet` for network-related daemons

Example (device-dependent):
```text
srw-rw---- 1 root inet   0 ... dnsproxyd
srw-rw---- 1 root inet   0 ... fwmarkd
srw-rw-rw- 1 root root   0 ... property_service
srw-rw-rw- 1 logd logd   0 ... logd
```

```bash
ls -l /dev/socket | head
ls -l /dev/socket/property_service 2>/dev/null
```

#### Android system properties = shared-memory reads + socket-mediated writes
- System properties are Android’s key/value “global config” mechanism (queried via `getprop`, written via `setprop`).
- Read path is designed to be fast:
  - processes `mmap()` one or more property areas from `/dev/__properties__/...` **read-only**
  - after mapping, reads are just memory loads (no IPC per read)
  - SELinux can still affect which property areas a domain can map/read
- Write path is centralized for security + ordering:
  - writes go to a Unix socket (commonly `/dev/socket/property_service`)
  - the property service validates the caller (UID/SELinux/property contexts) and updates the shared property area

Example: property areas mapped in a process (device-dependent):
```text
... /dev/__properties__/property_info
... /dev/__properties__/properties_serial
... /dev/__properties__/u:object_r:exported2_default_prop:s0
... /dev/__properties__/u:object_r:debug_prop:s0
... /dev/__properties__/u:object_r:heapprofd_prop:s0
... /dev/__properties__/u:object_r:vendor_socket_hook_prop:s0
... /dev/__properties__/u:object_r:vndk_prop:s0
```

```bash
cat /proc/$$/maps | grep __properties__ | head
getprop ro.build.fingerprint
```

##### Example: `setprop` denied by SELinux (unknown property → `default_prop`)
- If you try to set a random/unlabeled property name, it often maps to the catch-all property type `default_prop`.
- On production policies, the `shell` domain (`u:r:shell:s0`) is typically **not allowed** to `set` `default_prop`.

Example:
```bash
setprop adjasbdiasdbka askjbdasjhdas
# Failed to set property 'adjasbdiasdbka' to 'askjbdasjhdas'.
```

Corresponding logcat (example):
```text
avc: denied { set } for property=adjasbdiasdbka pid=11714 uid=2000 gid=2000 \
  scontext=u:r:shell:s0 tcontext=u:object_r:default_prop:s0 tclass=property_service permissive=0
```

Notes:
- The `tclass=property_service` and `tcontext=...:default_prop:s0` are the key clues:
  - property set operations are checked with Android’s SELinux **property service** class
  - the property name was labeled as `default_prop` (no specific `*property_contexts` match)
- You can confirm there is no explicit property_contexts entry:
```bash
grep -R "\<adjasbdiasdbka\>" /system/etc/selinux/*property_contexts 2>/dev/null
```
- The caller may also log an error code (example):
  - `Unable to set property ...: error code: 0x18`

#### RC Startup Files Control
- Service startup and management
- System property configuration
- Boot-time actions and triggers
- Process permissions and capabilities

### System Partitions (System / Vendor / ODM / Product)
- Android splits the OS stack across partitions so different teams/components can be updated and secured separately.
- Useful mental grouping:
  - **Platform**: `/system` (+ `/system_ext`)
  - **Hardware/Vendor**: `/vendor` (+ `/odm`)
  - **Product/SKU**: `/product`

#### System (`/system`)
- Core Android platform (framework, core libraries, core apps, base init RC, etc.)
- Often referred to as the **platform** layer.

#### System_ext (`/system_ext`) (if present)
- OEM extensions that are still treated as system components.

#### Vendor (`/vendor`)
- Hardware/SOC vendor components: HALs, vendor daemons/services, device-specific libraries/blobs, configs.

#### ODM (`/odm`)
- Original Design Manufacturer partition.
- Device-specific overlays/customizations on top of vendor (board variants).

#### Product (`/product`)
- Product/SKU-specific configs, apps, and features (regional/feature variants).

#### Data (`/data`)
- Writable partition for apps + user data.
- Common place for persistent properties and app/private data.

##### Mount points vs partitions vs images (common confusion)
- A **partition** is a region of storage exposed as a **block device** (e.g. `/dev/block/by-name/vendor`), which may contain:
  - a filesystem image (often `ext4` or `erofs`) → mounted at a directory like `/vendor`
  - raw structured data (e.g., `vbmeta`, `boot`, `dtbo`, `metadata`) → not “mounted” like a filesystem
- A **mount point** is just a directory in the VFS (e.g. `/vendor`) where a filesystem is attached.
- On many modern devices, `/system`, `/vendor`, `/product`, `/odm`, `/system_ext` are backed by **logical partitions** (device-mapper), so the backing device shows up as `/dev/block/dm-*` or `/dev/block/mapper/*`.

##### Block devices: physical partitions vs logical partitions (dm-*)
- **Physical partitions** are GPT entries on the flash (what `fastboot` typically thinks of as partitions).
  - On-device, they commonly appear under `/dev/block/by-name/*` (or `/dev/block/bootdevice/by-name/*`).
- **Logical partitions** (dynamic partitions) are created at boot by **device-mapper** from the `super` container.
  - They appear as `/dev/block/dm-*` and often get friendlier symlinks under `/dev/block/mapper/*`.
- Useful mental model:
  - `/dev/block/by-name/super` → container (not mounted)
  - `/dev/block/dm-*` / `/dev/block/mapper/*` → logical partitions like `system[_a]`, `vendor[_a]`, `product[_a]`, `odm[_a]`, ...

##### Quick mapping commands (mounts ↔ block devices)
```bash
# What is mounted where? (source device + mountpoint + fstype)
cat /proc/mounts | grep -E ' /(vendor|odm|product|system_ext) '
# Note: on "system-as-root" devices, the system image may be mounted at "/" (root), not "/system".
cat /proc/mounts | head

# What block devices exist at all?
cat /proc/partitions | head

# Physical partition names (symlinks) and what they point at
ls -l /dev/block/by-name 2>/dev/null | head
readlink /dev/block/by-name/super 2>/dev/null

# For dm devices: show dm name + what underlying devices they sit on
for dm in /sys/block/dm-*; do
  [ -e "$dm" ] || continue
  echo "== $dm =="
  cat "$dm/dm/name" 2>/dev/null
  ls -l "$dm/slaves" 2>/dev/null
  echo
done
```

##### SELinux tie-in
- Many SELinux files are also layered across partitions (e.g., `*sepolicy*.cil`, `*property_contexts`, `*service_contexts`).
- You’ll commonly see the same "concept" split as platform vs vendor vs product vs odm.

##### Quick directory checks
```bash
ls -d /system /system_ext /vendor /odm /product 2>/dev/null
mount | grep -E " /system | /vendor | /odm | /product | /system_ext "
```

##### Init tie-in
- Partition-specific init RC files can exist in multiple places, not just `/system/etc/init`.
- Common quick search:
```bash
find /system /vendor /odm /product -maxdepth 3 -type f -name "*.rc" 2>/dev/null | head
```

##### Firmware blobs (`/vendor/firmware`) (reverse engineering notes)
- Many hardware blocks in Android devices are controlled by their own embedded CPUs/DSPs (Wi-Fi, GPU, modem, sensor hub, audio DSP, video codecs, secure elements, etc.).
- Linux drivers typically load these opaque binaries using the kernel **firmware_class** interface (e.g., `request_firmware()`).
- On Android, vendor-provided firmware is commonly stored under:
  - `/vendor/firmware/`
  - sometimes `/vendor/firmware_mnt/` (device-dependent)
- Firmware is usually part of the **vendor image** (`vendor.img`) and is device/SoC specific.

###### Common formats / naming patterns (Qualcomm-heavy devices)
- `*.mdt` + `*.b00`..`*.bNN`
  - Common Qualcomm packaging for subsystem images (metadata + split segments).
  - You often need the matching `*.mdt` plus all corresponding `*.b*` chunks.
- `*.mbn`
  - Qualcomm signed image container (common for modem/WLAN/subsystems).
- `*.elf`
  - Standard ELF (often the easiest starting point for static analysis).
- `*.bin`
  - Raw binary blob (could be anything: microcode, model data, calibration, configs).
- `*.ftb` (touch), `*.wmfw` (Cirrus/Wolfson DSP), plus `*.xml` / `*.yaml` / `*.textproto` / `*.jsn` metadata/configs.

###### Practical workflow: collect + triage
```bash
# On-device inventory
adb shell ls -l /vendor/firmware 2>/dev/null | head
adb shell ls -l /vendor/firmware_mnt 2>/dev/null | head

# Pull to host for analysis
adb pull /vendor/firmware ./vendor_firmware

# If the directory is huge, pull a subset by prefix
adb pull /vendor/firmware/adsp.mdt .
adb pull /vendor/firmware/adsp.b* .
adb pull /vendor/firmware/a640_zap.elf .
adb pull /vendor/firmware/venus.mdt .
adb pull /vendor/firmware/venus.b* .
```

###### Mapping firmware -> what loads it (kernel + remote processors)
- If the device exposes remote processors via **remoteproc**, you can often see the *requested firmware name* in sysfs.
  - (Availability depends on kernel + permissions; may require root.)

```bash
# Enumerate remote processors and see (name, firmware, state)
adb shell '
for r in /sys/class/remoteproc/remoteproc*; do
  [ -e "$r" ] || continue
  echo "== $r =="
  cat "$r/name" 2>/dev/null
  cat "$r/firmware" 2>/dev/null
  cat "$r/state" 2>/dev/null
  echo
 done'

# Kernel logs can also reveal request_firmware() names (access varies by build)
adb shell dmesg 2>/dev/null | grep -i firmware | tail
adb shell logcat -b kernel -d 2>/dev/null | grep -i firmware | tail
```

###### Example: Pixel 4 (flame) `/vendor/firmware` inventory (excerpt)
```text
flame:/vendor/firmware # ls
adsp.mdt
adsp.b00
...
cdsp.mdt
cdsp.b00
...
slpi.mdt
slpi.b00
...
a640_zap.elf
a640_gmu.bin
venus.mdt
venus.b00
...
bdwlan-flame.bin
wlanmdsp.mbn
widevine.mdt
widevine.b00
...
```

Rough mental mapping (names vary by device):
- `adsp*` / `cdsp*` / `slpi*`: Qualcomm Hexagon DSP subsystems (audio / compute / sensors).
- `venus*`: video codec firmware.
- `a640_*`: Adreno GPU firmware/microcode for that generation.
- `bdwlan*` / `wlan*`: Wi-Fi firmware.
- `widevine*`, `confirmationui*`, secure-element firmware directories, etc.: DRM/TEE/secure-world related payloads (commonly signed/encrypted).

###### Reverse engineering notes (what is realistic)
- Many firmware images are **signed** (and sometimes encrypted). Static analysis is still possible, but patching/flashing is often blocked on locked devices.
- Start with:
  - `*.elf` (readelf + Ghidra/IDA)
  - config/metadata files (`.xml`, `.yaml`, `.textproto`, `.jsn`) to understand runtime wiring
  - `strings`/`hexdump` on unknown blobs to find identifiers, version strings, compression markers, etc.

### Dynamic Partitions & `super` (liblp)
- Many modern Android devices group multiple logical partitions into one big physical GPT partition called **`super`**.
- Inside `super` you get **dynamic logical partitions** (e.g., `system`, `vendor`, `product`, `odm`, `system_ext`).
- Logical partitions are exposed via **device-mapper** (often as `/dev/block/dm-*` or `/dev/block/mapper/*`).

#### Physical vs logical partitions (what you’ll actually see)
- The `super` block device is usually **not mounted**; it’s a container that’s parsed at boot.
- Mounts like `/vendor` or `/product` will often show a **dm** source (e.g., `/dev/block/dm-3` or `/dev/block/mapper/vendor_a`).
- To map a `dm-*` back to a logical partition name + see what it sits on top of:
  - `cat /sys/block/dm-3/dm/name`
  - `cat /sys/block/dm-3/dm/uuid` (hints at `verity` / `crypt` / `snapshot` / etc.)
  - `ls -l /sys/block/dm-3/slaves/`

```bash
# Show the backing block device + filesystem type for key mounts (source mountpoint fstype)
cat /proc/mounts | awk '$2=="/" || $2=="/system" || $2=="/vendor" || $2=="/odm" || $2=="/product" || $2=="/system_ext" {print $1, $2, $3}'

# For each dm device: dm-* → (dm/name, dm/uuid) + slaves (backing chain)
for dm in /sys/block/dm-*; do
  [ -e "$dm" ] || continue
  echo "$(basename "$dm") name=$(cat "$dm/dm/name" 2>/dev/null) uuid=$(cat "$dm/dm/uuid" 2>/dev/null)"
  ls -l "$dm/slaves" 2>/dev/null
  echo
done
```

#### dm stack: why a single mount can involve multiple dm devices
- Android often layers multiple device-mapper targets:
  - `linear` → basic logical partition mapping (common for dynamic partitions)
  - `verity` → dm-verity for Verified Boot (often for `/system`, `/vendor`, `/product`)
  - `snapshot` / `cow` → virtual A/B (OTA) snapshots
  - `crypt` / `dm-default-key` → encryption layers (common for `/data`, sometimes metadata)
- This is why you may see `dm-` devices stacked on top of other `dm-` devices.

```bash
# Inspect dm tables (targets like linear/verity/snapshot/crypt/...)
for t in /sys/block/dm-*/dm/table; do
  [ -e "$t" ] || continue
  echo "== $t =="
  cat "$t"
  echo
done
```

#### What `super` buys you
1) **No GPT repartitioning for updates**
   - You can resize/add/remove logical partitions by changing metadata inside `super`.
2) **Flexible space allocation**
   - Space can be shifted between `system/vendor/product/...` over time as the OS evolves.
   - Reduces “wasted” fixed partition sizing.

#### `liblp` and friends
- **liblp** is Android’s “logical partition” library.
- Tools (availability varies): `lpdump`, `lpmake`, `lpadd`, `lpunpack`.

#### Useful commands
```bash
# Find the physical super partition
ls -l /dev/block/by-name/super 2>/dev/null

# List physical partitions by name (GPT entries)
ls -l /dev/block/by-name 2>/dev/null | head

# See dm devices + their names
ls -l /dev/block/dm-* 2>/dev/null
for f in /sys/block/dm-*/dm/name; do echo "$f: $(cat $f)"; done

# If lpdump exists, inspect logical partitions inside super
which lpdump 2>/dev/null && lpdump /dev/block/by-name/super

# A/B metadata + snapshots often use these partitions
ls -l /dev/block/by-name/metadata 2>/dev/null
ls -l /dev/block/by-name/misc 2>/dev/null
```

### Seamless (A/B) System Updates (“slots”)
- Devices that use **A/B (seamless) updates** have two copies (“slots”) of many critical partitions.
  - You’ll commonly see them as `*_a` and `*_b` partitions (sometimes thought of as “primary” and “backup”).
- The device boots from the **active slot**; updates are written to the **inactive slot**.
- If the update boots successfully, the new slot is marked successful; if it fails, the bootloader can **roll back** to the old slot.

#### Why it uses extra flash space
- Traditional A/B needs space for two sets of partitions (A and B).
- Newer devices may use **virtual A/B** (snapshots) to reduce duplication, but there’s still reserved space for safe updates.

#### Traditional A/B vs Virtual A/B (snapshots)

##### Traditional A/B (two full copies)
- You can often see two copies (or two logical layouts) like:
  - `system_a` + `system_b`
  - `vendor_a` + `vendor_b`

##### Virtual A/B (snapshot / COW)
- Instead of writing a full “B” copy up front, the OTA uses **snapshots** with **COW (copy-on-write)** storage.
- You may see block devices/partitions like:
  - `system_a-cow`, `vendor_a-cow`, etc.
- The OTA is applied to the snapshot, then **merged** back into the base partition after boot.

#### What happens during an OTA (high level)

##### Traditional A/B flow
1) Device is running from slot **A**.
2) OTA writes new images into slot **B** partitions.
3) Reboot → bootloader switches active slot to **B**.
4) If boot succeeds, slot B is marked successful; otherwise rollback to A.

##### Virtual A/B flow
1) Device is running from slot **A**.
2) OTA creates snapshot devices + `*-cow` storage and applies changes there.
3) Reboot → the system boots through snapshot mappings.
4) Background merge commits snapshot data into the base partitions.
5) After merge, snapshots/cows are torn down.

#### Useful commands
```bash
# Current slot info
getprop ro.boot.slot_suffix
getprop ro.boot.slot_successful

# Look for snapshot/cow related block devices
ls -l /dev/block/by-name 2>/dev/null | grep -i cow
ls -l /dev/block/mapper 2>/dev/null | grep -i -E 'cow|snapshot'

# Snapshot merge helper (device-dependent)
ps -ef | grep -i snapuserd
getprop init.svc.snapuserd
```

#### Find the current slot
```bash
getprop ro.boot.slot_suffix          # often: _a or _b
getprop ro.boot.slot                 # sometimes: a or b
cat /proc/cmdline | tr ' ' '\n' | grep -i slot
```

#### Inspect slot partitions
```bash
# Common on Android
ls -l /dev/block/by-name 2>/dev/null | grep -E '_a$|_b$' | head
```

#### bootctl (if available)
```bash
bootctl get-current-slot
bootctl get-number-slots
bootctl get-suffix
```

#### OTA updater logs (often update_engine)
```bash
ls -l /data/misc/update_engine* 2>/dev/null
```

#### Fastboot (host-side; run on your computer in bootloader/fastboot mode)
```bash
fastboot getvar current-slot
fastboot getvar slot-count
fastboot --set-active=a   # or b
```

#### Interpreting `fastboot getvar all` (bootloader mode)
- Useful for quickly confirming: device codename, A/B slot state, unlock state, secure boot mode, snapshot/virtual A/B status.
- Common fields:
  - `product:` device codename.
    - Safety: this should match the factory image / OTA package you intend to flash.
  - `slot-suffixes:` e.g. `_a,_b`
  - `slot-count:` number of slots (commonly 2)
  - `current-slot:` bootloader's active slot (e.g. `a`)
  - `unlocked:` bootloader unlock state
  - `secure-boot:` often `PRODUCTION` on shipping devices
  - `is-userspace:` `no` = bootloader fastboot, `yes` = userspace fastboot (`fastbootd`)
  - `snapshot-update-status:` snapshot state for virtual A/B (if supported)

Example excerpt (Pixel 4 `flame`):
```text
(bootloader) product:flame
(bootloader) slot-suffixes:_a,_b
(bootloader) slot-count:2
(bootloader) current-slot:a
(bootloader) unlocked:yes
(bootloader) secure-boot:PRODUCTION
(bootloader) is-userspace:no
(bootloader) snapshot-update-status:none
```

Slot-health fields you'll commonly see:
- `slot-successful:<slot>:{yes|no}`: whether a slot was marked as having booted successfully.
- `slot-unbootable:<slot>:{yes|no}`: whether the slot is marked unbootable (often after repeated failed boots).
- `slot-retry-count:<slot>:<n>`: remaining retries before marking unbootable (bootloader-specific).

```bash
# Dump everything
fastboot getvar all

# Minimal "am I about to flash the right thing?" sanity
fastboot getvar product
fastboot getvar current-slot
fastboot getvar unlocked
```

#### Factory images (Pixel-style) and what "flash-all" actually does
- A Google factory image zip commonly contains:
  - `flash-all.bat` / `flash-all.sh`: host-side flashing scripts (fastboot wrappers)
  - `bootloader-<device>-<ver>.img`: bootloader package
  - `radio-<device>-<ver>.img`: baseband/modem firmware package
  - `image-<device>-<build>.zip`: bulk partition images (exact set varies)

Example unzip output (excerpt):
```text
bootloader-caiman-....img
radio-caiman-....img
image-caiman-....zip
flash-all.bat
flash-all.sh
...
```

Typical flow in `flash-all.bat`:
```text
fastboot flash bootloader bootloader-....img
fastboot reboot-bootloader
fastboot flash radio radio-....img
fastboot reboot-bootloader
fastboot -w update image-....zip
```

Notes:
- `fastboot -w` wipes userdata (`/data`).
- `fastboot update <zip>` is a convenient way to flash many partitions at once.

Reverse engineering workflow (read-only):
```bash
# List what's inside the image zip
unzip -l image-<device>-<build>.zip | head

# Extract a small subset for analysis (names are build-dependent)
unzip image-<device>-<build>.zip boot.img vendor_boot.img vbmeta.img dtbo.img 2>/dev/null
```

#### Qualcomm FBPK bootloader packages (example: `imjtool` output)
- Some Qualcomm-based bootloader images are containers (e.g. "FBPK") holding multiple sub-images:
  - `abl` (Android Bootloader / fastboot implementation)
  - `bl31` (ARM Trusted Firmware runtime at EL3)
  - `tzsw` (TrustZone secure-world payload)
  - plus platform-specific early boot stages and firmware updates (names vary)

Example (excerpt):
```text
QCom "FBPK" (v2) image detected
...
9:  abl  (...)
10: bl31 (...)
11: tzsw (...)
...
```

RE tips:
- Extract sub-images (use your tool's `--help` to find the extract option), then run `file`, `strings`, `readelf` and open `*.elf` in Ghidra/IDA.
- It's normal for many boot-chain images to be signed (and sometimes encrypted). Treat this as mostly read-only on production devices.

#### Extracting `fastboot oem` commands (static)
- The `fastboot oem ...` subcommands are typically implemented in the bootloader's fastboot component (often `abl` on Qualcomm devices).
- A quick way to enumerate hidden OEM commands is to extract `abl`, then grep its strings.
- If your FBPK tool supports it, prefer an `extract` mode (cleaner than manual `dd` carving).

```bash
# 0) Your bootloader package (FBPK container)
BOOTLOADER=bootloader-<device>-<ver>.img

# Option A (preferred): use the container tool to extract sub-images
imjtool.ELF64 "$BOOTLOADER" extract
ABL=extracted/abl

# Option B: carve out ABL with dd (use offset/size from the tool's listing)
# Example: abl (0x20d000 bytes @offset: 0x98400)
# dd if="$BOOTLOADER" of=abl.bin bs=1 skip=$((0x98400)) count=$((0x20d000))
# ABL=abl.bin

# 1) Collect "usage-ish" lines (best signal / least noise)
strings -a -n 3 "$ABL" \
  | grep -E '(^INFOoem |^INFO  oem |usage: oem |fastboot oem |Default test: oem |^INFO<[0-9]+> oem )' \
  | sort -u > oem_usage.txt

# 2) Extract a canonicalized command list (up to 3 tokens after oem)
# Good for grouping nested commands like: "oem gsc id".
cat oem_usage.txt \
  | grep -oE 'oem [a-z0-9][a-z0-9_-]*( [a-z0-9][a-z0-9_-]*){0,2}' \
  | sort -u > oem_cmds.txt

# Optional: show as fastboot invocations
sed 's/^oem /fastboot oem /' oem_cmds.txt | head

# Optional: direct binary scan (can include false positives like internal thread names)
# grep -aoP 'oem\s+[a-z0-9][a-z0-9_-]*(?:\s+[a-z0-9][a-z0-9_-]*){0,2}' "$ABL" | sort -u
```

Notes:
- Some commands are runtime-gated. Strings you may literally see:
  - "not allowed when locked"
  - "not allowed in prod mode"
- Treat anything involving `fuse`, `reprovision`, `factory-lock`, `ufs purge`, or `cmdline set/add/del` as potentially device-changing.

Example commands observed in one Pixel bootloader ABL (subset):
- `fastboot oem dmesg`
- `fastboot oem pkvm status`
- `fastboot oem udfps status`
- `fastboot oem uart list`
- `fastboot oem tmu temp`
- `fastboot oem gsc id`
- `fastboot oem gsc version`
- `fastboot oem gsa version`

#### Hands-on exercises (partitions, block devices, slots)
1) **Identify what backs `/vendor` / `/odm` / `/product` (device + FS type)**
   - `cat /proc/mounts | awk '$2=="/vendor" || $2=="/odm" || $2=="/product" {print $1, $2, $3}'`
   - If the source is `/dev/block/dm-*`, you’re looking at a **logical** partition.

2) **Map a `dm-*` to a logical partition name**
   - Example: if `/vendor` is backed by `/dev/block/dm-7`:
     - `cat /sys/block/dm-7/dm/name`
     - `ls -l /sys/block/dm-7/slaves/`

3) **Confirm whether the device uses dynamic partitions (`super`)**
   - `ls -l /dev/block/by-name/super 2>/dev/null`
   - `ls -l /dev/block/dm-* 2>/dev/null | head`

4) **A/B sanity**
   - `getprop ro.boot.slot_suffix`
   - `ls -1 /dev/block/by-name 2>/dev/null | grep -E '_a$|_b$' | head`

5) **Virtual A/B indicators (snapshots / COW)**
   - `ps -ef | grep -i snapuserd`
   - `ls -l /dev/block/mapper 2>/dev/null | grep -i -E 'cow|snapshot'`

6) **Correlate “which image came from where” via fingerprints**
   - `getprop | grep -E '^\[ro\.(build|system|vendor|odm|product)\.build\.fingerprint\]'`

---

## 4. Android Runtime

### Dalvik (Deprecated)
- Original virtual machine used in Android (up to Android 4.4 KitKat)
- **JIT (Just-In-Time) compilation**: Code compiled at runtime during app execution
- Uses `.dex` (Dalvik Executable) bytecode format
- Optimized for devices with limited memory and processing power
- Each app runs in its own Dalvik VM instance
- **Replaced by ART in Android 5.0+**

### ART (Android Runtime)
- Current runtime environment for Android (Android 5.0+)
- **AOT (Ahead-Of-Time) compilation**: Apps compiled during installation
- Also supports JIT compilation (hybrid approach in newer versions)
- Improved performance compared to Dalvik
- Better garbage collection with reduced pauses
- Enhanced debugging capabilities

### Dalvik vs ART Comparison
| Feature | Dalvik | ART |
|---------|--------|-----|
| Compilation | JIT (runtime) | AOT + JIT (hybrid) |
| Install time | Faster | Slower (due to compilation) |
| App launch | Slower | Faster |
| Storage | Less space | More space (compiled code) |
| Battery | Higher usage | More efficient |
| Garbage Collection | Older algorithm | Improved, concurrent GC |

### Zygote Process
- **Zygote**: Special Android process that serves as a template for launching apps
- Pre-loads common libraries and resources into memory
- When a new app is launched, Zygote forks itself creating a new process
- Much faster than starting apps from scratch

#### Multiple Zygote Processes
- **`zygote64`**: 64-bit Zygote process (primary on modern devices)
- **`zygote`**: 32-bit Zygote process (for backward compatibility)
- **`webview_zygote`**: Specialized Zygote for WebView processes

#### 32-bit Support
- **Android versions < 13**: Include 32-bit Zygote support
- **Android 13+**: May drop 32-bit support on 64-bit-only devices
- Allows running legacy 32-bit apps on 64-bit hardware

#### Example Process List
```bash
ps -ef | grep zygo
```
```text
root   901   1  zygote64        # 64-bit Zygote
root   905   1  zygote          # 32-bit Zygote
webview_zygote 2018  905  webview_zygote  # WebView Zygote
```

#### CPU Architecture Detection
```bash
cat /proc/cpuinfo | grep part
```
- Shows CPU part numbers for each core
- Different part numbers indicate big.LITTLE architecture
  - Example: `0x805` = Performance cores, `0x804` = Efficiency cores

---

## 5. Inter-Process Communication

### Android Binder
- **IPC mechanism** in Android
- Custom implementation built into the Linux kernel as a driver
- Enables communication between different processes and the Android system

#### Key Concepts
- **Binder Driver**: Kernel-level driver (`/dev/binder`) that facilitates IPC
- **Service Manager**: System service that maintains a registry of all Binder services
- **IBinder Interface**: Base interface for all Binder objects
- **AIDL (Android Interface Definition Language)**: Used to define IPC interfaces

#### How Binder Works
- Processes communicate by sending transactions through the Binder driver
- Client processes bind to services via Binder references
- Data is marshalled/unmarshalled for cross-process communication
- More efficient than traditional Linux IPC (pipes, sockets)

#### Use Cases
- System services (ActivityManager, PackageManager, etc.)
- Inter-app communication
- Client-server architecture within Android
- Remote procedure calls between processes

### Service Management

#### Listing Services
```bash
service list | grep -v /
```
- **`service list`**: Lists all registered Binder services on the device
- **`grep -v /`**: Filters out services with `/` in their name (excludes AIDL interface paths)
- Shows only service names without interface paths
- Services are registered with the Service Manager

#### Common System Services
- `activity`: ActivityManagerService
- `package`: PackageManagerService
- `window`: WindowManagerService
- `alarm`: AlarmManagerService
- `connectivity`: ConnectivityService
- `battery`: BatteryService

---

## 6. Development & Debugging Tools

### BDSM (Boot Development and System Management)
- Tool for Android boot development and system management
- **Use cases**:
  - Analyzing boot sequences
  - Debugging init processes
  - Managing system services
  - Testing boot configurations

### jtrace64
- 64-bit Java tracing tool for Android
- **Use cases**:
  - Runtime analysis of Android applications
  - Java/Kotlin code tracing
  - Performance profiling
  - Debugging native and Java interactions

### Runtime Resource Overlays (RRO) / OverlayManager (`cmd overlay`)
- **What it is:** Android’s overlay system (RRO) lets the system apply alternate resources from an overlay package on top of a target package.
- Managed by **OverlayManagerService (OMS)**; you can interact with it from a device shell via `cmd overlay`.

#### List overlays
```bash
cmd overlay list
```
- Output often prefixes overlays with a checkbox-like marker:
  - `[x]` = enabled
  - `[ ]` = disabled

Example (disabled overlay):
```text
[ ] com.android.internal.systemui.navbar.gestural
```

#### Enable / disable an overlay
```bash
# enable
cmd overlay enable com.android.internal.systemui.navbar.gestural

# disable
cmd overlay disable com.android.internal.systemui.navbar.gestural
```

Notes:
- From your computer, run the same commands via ADB:
  - `adb shell cmd overlay list`
  - `adb shell cmd overlay enable <overlayPackage>`
- You may need to specify the user on multi-user devices (common default is user 0):
  - `cmd overlay enable --user 0 <overlayPackage>`
- UI-related overlays can be immediate, but may require restarting the affected app (e.g., SystemUI) to fully apply.

### `aapt` / `aapt2` (inspect APKs: manifest + resources)
- **What it is:** Android Asset Packaging Tool(s) from the Android SDK **Build-Tools**.
- Useful when you have an APK and want to inspect the **compiled (binary) XML** manifest/resources without installing.

#### Dump the manifest XML tree
- Prints a readable tree for `AndroidManifest.xml` (which is binary-encoded inside an APK).

```bash
# aapt (legacy CLI)
# ("dump" can be shortened to "d")
aapt d xmltree "Facebook Lite_499.0.0.0.2_APKPure.apk" AndroidManifest.xml

# aapt2 (newer CLI)
aapt2 dump xmltree --file AndroidManifest.xml "Facebook Lite_499.0.0.0.2_APKPure.apk"
```

How to read the output:
- `E:` = XML **element**
- `A:` = **attribute** (name/type/value)

#### Quick high-level info (“badging”)
```bash
aapt d badging app.apk
aapt2 dump badging app.apk
```
- Commonly includes package name, version, `sdkVersion` / `targetSdkVersion`, and launchable activity.

#### Common gotcha: tool not on PATH
- `aapt`/`aapt2` usually live under Android SDK Build-Tools, e.g.:
  - `$ANDROID_SDK_ROOT/build-tools/<version>/aapt`
  - `$ANDROID_SDK_ROOT/build-tools/<version>/aapt2`
- If your shell can’t find `aapt`, run it via the full path.

### Task snapshots / Recents thumbnails (`/data/system_ce/<user>/snapshots`)
- Android can store **snapshot images** of running/recent tasks (used for the Recents/task switcher UI).
- On some devices/versions you can see them under:
  - `/data/system_ce/0/snapshots` (for user 0)
- Directory contents are often **numbered** and come in sets:
  - `<id>.jpg` (snapshot image)
  - `<id>_reduced.jpg` (smaller/low-res snapshot)
  - `<id>.proto` (metadata for that snapshot)

Example:
```text
21.jpg
21.proto
21_reduced.jpg
```

### Activity Manager (`am`) + OOM adjustment (`am dump oom`)
- **`am`** (Activity Manager) is a device-shell CLI that talks to **ActivityManagerService**.
- `am dump oom` shows how Android categorizes processes for low-memory killing and the current **OOM adjustment** (priority) assigned to each process.

#### Dump OOM levels + per-process OOM info
```bash
am dump oom
```
- Output is usually split into:
  - **OOM levels**: adj categories + their thresholds (often shown in KB, like `(...K)`).
  - **Process OOM control**: per-process lines showing the current/set OOM adj and state.

#### How to interpret OOM adj numbers
- **Lower / more negative** adj = **more important** (harder to kill)
  - Examples: `SYSTEM_ADJ` (e.g. `-900`), `PERSISTENT_PROC_ADJ` (e.g. `-800`)
- **Higher** adj = **less important** (easier to kill)
  - Examples: cached app ranges (e.g. `CACHED_APP_MIN_ADJ` ~ `900` and `CACHED_APP_MAX_ADJ` ~ `999`)

#### OOM levels (rough kill priority)
- Think of this as an **importance ladder**.
  - **Kill first**: higher adj (cached) → lower importance
  - **Kill last**: negative adj (system/persistent) → higher importance

From **most protected** → **most killable** (example from `am dump oom`):
- `-900` SYSTEM_ADJ
- `-800` PERSISTENT_PROC_ADJ
- `-700` PERSISTENT_SERVICE_ADJ
- `0` FOREGROUND_APP_ADJ
- `100` VISIBLE_APP_ADJ
- `200` PERCEPTIBLE_APP_ADJ
- `250` PERCEPTIBLE_LOW_APP_ADJ
- `300` BACKUP_APP_ADJ
- `400` HEAVY_WEIGHT_APP_ADJ
- `500` SERVICE_ADJ
- `600` HOME_APP_ADJ
- `700` PREVIOUS_APP_ADJ
- `800` SERVICE_B_ADJ
- `900` CACHED_APP_MIN_ADJ
- `999` CACHED_APP_MAX_ADJ

Kill order (first → last) is the reverse:
- `999` cached max → … → `-900` system

Rule of thumb:
- Under memory pressure, Android typically reclaims memory by killing processes starting at the **highest** adj (cached) and working downward until enough memory is freed (not always strictly one-by-one; size/heuristics matter).

#### Common fields in “Process OOM control”
- `oom: max=... curRaw=... setRaw=... cur=... set=...`
  - `cur*` = current computed values
  - `set*` = what was last applied to the kernel/LMK
- `state: cur=... set=... lastPss=... lastSwapPss=...`
  - PSS numbers are a rough “how much RAM” signal (from the last sample)
- `cached=` / `empty=` flags give a quick hint about whether the process is considered cache-only.

Host-side equivalent:
- `adb shell am dump oom`

### Kernel OOM scoring (`/proc/<pid>/oom_score*`)
- Per-process files under `/proc/<pid>/` that influence/describe how likely the kernel is to kill a process during an **out-of-memory (OOM)** event.

#### `oom_score` (read)
- A 0–1000-ish “badness” score.
- **Higher = more likely to be selected** by the kernel OOM killer.
- On many kernels it already reflects any adjustment made via `oom_score_adj` / `oom_adj`.

#### `oom_score_adj` (read/write; preferred)
- Adjustment knob in the range **-1000 .. +1000**.
- Conceptually, the kernel applies this adjustment to the base badness score before choosing a victim.
  - **-1000** = effectively “don’t kill this process for OOM” (score becomes 0 / exempt).
  - **0** = default
  - **+1000** = make it as killable as possible

#### `oom_adj` (legacy)
- Older interface (commonly **-17 .. +15**) that maps onto `oom_score_adj`.
  - `oom_adj = -17` corresponds to `oom_score_adj = -1000`.
- Still shows up on some Android/vendor kernels for compatibility.

Example (protected process):
```text
oom_adj:       -17
oom_score_adj: -1000
oom_score:     0
```

Rule of thumb:
- When the system hits OOM, the kernel typically tries to kill an eligible process with the **highest** OOM badness/score (excluding processes marked as non-killable via `oom_score_adj=-1000`).

Host-side equivalents:
- `adb shell cat /proc/<pid>/oom_score`
- `adb shell cat /proc/<pid>/oom_score_adj`

### LMKD (Low Memory Killer Daemon) vs kernel OOM killer
- **LMKD** is a userspace daemon that tries to reclaim memory **before** the system hits a kernel OOM.
- It uses the **process importance** information (OOM adj / `oom_score_adj`) that Android computes (primarily via **ActivityManagerService** for app processes).

Key points:
- LMKD does **not** “only assist the kernel” — it typically **selects and kills processes itself** (it’s a proactive killer).
- The **kernel OOM killer** is a separate last-resort mechanism that triggers when the kernel can’t satisfy allocations; it can select from **any killable process**, not only ones “registered” with ActivityManager.
- In practice, the processes ActivityManager tracks are the ones with the most meaningful **OOM adj tiers** (foreground/visible/cached), so LMKD’s victims are often app processes with **high** `oom_score_adj` (cached/background).

### Screenshot capture (`screencap` + `adb pull`)
- `screencap` runs **on-device** and writes a screenshot image to a file.
- A common workflow is: save to `/data/local/tmp/` on device → pull it to the host with `adb pull`.

```bash
# from host
adb shell screencap /data/local/tmp/capture.png
adb pull /data/local/tmp/capture.png

# (or) if you’re already in `adb shell`
# screencap /data/local/tmp/capture.png
```

Example output (host):
```text
/data/local/tmp/capture.png: 1 file pulled, 0 skipped. 0.5 MB/s (15106 bytes in 0.029s)
```

Notes:
- `adb` is a **host-side** tool (don’t try to run `adb pull` from inside `adb shell`).
- On some older builds you may see `screencap -p <file>` to force PNG output.

### Capturing input events (`getevent -l`)
- `getevent` reads Linux input events from `/dev/input/event*` and prints them.
- `-l` prints human-readable **labels** for event types/codes.

```bash
# from host
adb shell getevent -l
adb shell getevent -l /dev/input/event2

# (or) if you’re already in `adb shell`
# getevent -l
```

Example output (snippet):
```text
add device 1: /dev/input/event2
  name:     "fts"
add device 2: /dev/input/event0
  name:     "qpnp_pon"
add device 3: /dev/input/event1
  name:     "gpio-keys"

/dev/input/event2: EV_KEY BTN_TOUCH DOWN
/dev/input/event2: EV_ABS ABS_MT_TRACKING_ID 0000006a
/dev/input/event2: EV_ABS ABS_MT_POSITION_X  000001f0
/dev/input/event2: EV_ABS ABS_MT_POSITION_Y  000008c7
/dev/input/event2: EV_SYN SYN_REPORT         00000000
...
/dev/input/event2: EV_ABS ABS_MT_TRACKING_ID ffffffff
/dev/input/event2: EV_KEY BTN_TOUCH UP
```

What you’ll typically see:
- Device discovery lines:
  - `add device ... /dev/input/eventN` + `name: "..."`
- Repeating event frames ending in:
  - `EV_SYN SYN_REPORT 00000000`

Common touch-related fields:
- `EV_KEY BTN_TOUCH DOWN/UP` = touch contact started/ended
- `EV_ABS ABS_MT_TRACKING_ID <id>` = multitouch contact tracking id
  - `ffffffff` usually indicates “end of contact”
- `EV_ABS ABS_MT_POSITION_X / Y` = touch coordinates
- `EV_ABS ABS_MT_PRESSURE` = pressure (device-dependent)

Permissions note:
- Access to `/dev/input/event*` is often controlled via the `input` group (AID_INPUT=1004) **and** SELinux.

### UI hierarchy dump (`uiautomator dump`)
- Dumps the current UI **view hierarchy** (what UI Automator / accessibility can “see”) to an XML file.
- Default output path is usually:
  - `/sdcard/window_dump.xml`

```bash
# from host
adb shell uiautomator dump /sdcard/window_dump.xml
adb pull /sdcard/window_dump.xml

# (optional) view it without pulling
adb shell cat /sdcard/window_dump.xml

# (or) if you’re already in `adb shell`
# uiautomator dump /sdcard/window_dump.xml
# cat /sdcard/window_dump.xml
```

Example output (command):
```text
UI hierchary dumped to: /sdcard/window_dump.xml
```

What the XML contains:
- Root `<hierarchy rotation="...">`
- Many `<node ... />` entries with attributes like:
  - `text`, `resource-id`, `class`, `package`, `content-desc`
  - `clickable`, `enabled`, `focusable`, `scrollable`, etc.
  - `bounds="[x1,y1][x2,y2]"`

Snippet:
```xml
<hierarchy rotation="0">
  <node class="android.widget.FrameLayout" package="com.google.android.youtube" bounds="[0,0][1080,2148]">
    ...
  </node>
</hierarchy>
```

Notes:
- Some UI elements (e.g., content rendered by `SurfaceView`/`TextureView`, or non-accessible custom drawing) may not appear.

---

## 7. Exercises (hands-on)
These are short drills to reinforce the notes. If something needs root, it’s marked.

### Exercise 1: ADB sanity + device identity
```bash
adb devices
adb shell id
adb shell getprop ro.product.model
adb shell getprop ro.build.fingerprint
```
Write down:
- model + build fingerprint
- your UID/GID + group list

### Exercise 2: Find Bionic libc (APEX vs bootstrap)
```bash
# APEX-provided libc
adb shell ls -al /system/lib64/libc.so
adb shell readlink /system/lib64/libc.so
adb shell ls -al /apex/com.android.runtime/lib64/bionic/libc.so

# Bootstrap copy (if present)
adb shell ls -al /system/lib64/bootstrap 2>/dev/null
adb shell ls -al /system/lib64/bootstrap/libc.so 2>/dev/null

# Check what a running process maps (example: system_server)
adb shell pidof system_server
adb shell 'PID=$(pidof system_server); cat /proc/$PID/maps | grep libc.so | head'
```
Goal: confirm the `/system/lib64/libc.so` symlink points into `/apex/com.android.runtime/...`, and see whether bootstrap libc exists + which one a live process is using.

### Exercise 3: Pull an installed APK + inspect its manifest
Pick a package that exists (example: `com.google.android.youtube`).
```bash
adb shell pm path com.google.android.youtube
```
Copy the path you get (often ends in `base.apk`) and pull it:
```bash
adb pull /data/app/.../base.apk youtube.apk
```
Then on host:
```bash
aapt2 dump badging youtube.apk
aapt2 dump xmltree --file AndroidManifest.xml youtube.apk
```
Find:
- package name + version
- `sdkVersion` / `targetSdkVersion`
- at least 3 `<uses-permission>` entries

### Exercise 4: Permissions inventory
```bash
adb shell pm list permissions
adb shell "dumpsys package com.google.android.youtube | grep -i permission"
```
Goal: spot platform permissions (`android.permission.*`) vs app-defined (`com.*`).

### Exercise 5: Screenshot workflow
```bash
adb shell screencap /data/local/tmp/capture.png
adb pull /data/local/tmp/capture.png
adb shell rm /data/local/tmp/capture.png
```
Goal: get a clean “device → host” screenshot loop.

### Exercise 6: Dump the UI hierarchy (UI Automator)
```bash
adb shell uiautomator dump /sdcard/window_dump.xml
adb pull /sdcard/window_dump.xml
```
Open the XML and find:
- a node with a non-empty `resource-id`
- a node with a non-empty `content-desc`
- the `bounds` for something clickable

### Exercise 7: Map touch events to `/dev/input/event*`
List devices + capabilities:
```bash
adb shell getevent -lp
```
Then monitor one device (replace `event2`):
```bash
adb shell getevent -l /dev/input/event2
```
Tap/swipe and note which event device emits `BTN_TOUCH` and changing `ABS_MT_POSITION_X/Y`.

### Exercise 8: Inspect OOM adj tiers
```bash
adb shell am dump oom
```
Goal: identify which adj tier your foreground app vs cached apps fall into.

Optional (root may be required on some builds):
```bash
adb shell pidof system_server
adb shell cat /proc/<pid>/oom_score
adb shell su -c "cat /proc/<pid>/oom_score_adj" 2>/dev/null
```

### Exercise 9: Overlay inventory (optional)
```bash
adb shell cmd overlay list
```
Goal: find one enabled (`[x]`) and one disabled (`[ ]`) overlay.

Optional toggle (if permitted), then revert:
```bash
adb shell cmd overlay enable <overlayPackage>
adb shell cmd overlay disable <overlayPackage>
```

### Exercise 10: Task snapshots (root-only, optional)
```bash
adb shell su -c "ls -l /data/system_ce/0/snapshots | head"
```
Goal: confirm snapshots exist, then pull one JPG by name.

### Exercise 11: Inject UI input over adb (`input`)
```bash
# Go Home
adb shell input keyevent KEYCODE_HOME

# Launch an app (replace package)
adb shell monkey -p com.google.android.youtube 1

# Find your screen size (so you pick valid coordinates)
adb shell wm size

# Tap + swipe (adjust coordinates for your device)
adb shell input tap 500 500
adb shell input swipe 500 1600 500 300 300
```
Goal: combine this with Exercise 5 (take a screenshot) to confirm your injected input changed the UI.

### Exercise 12: Decode `/data/system/packages.list` columns (root likely required)
```bash
# View a few lines
adb shell su -c "head -n 20 /data/system/packages.list"

# Pick a package and decode its 8 fields
adb shell su -c "grep '^com.google.android.youtube ' /data/system/packages.list"

# Cross-check with PackageManager output
adb shell "pm list packages -U | grep com.google.android.youtube"
adb shell "dumpsys package com.google.android.youtube | grep -E 'userId=|versionCode|seinfo|gids'"

# Find packages that have inet (3003) as a supplemental GID
adb shell su -c "grep -E '(^|[ ,])3003([ ,]|$)' /data/system/packages.list | head"
```
Goal: annotate the 8 fields for one line and explain what the `gids` column implies (e.g., `3003(inet)` for networking on paranoid-network kernels).

### Exercise 13: Decode a permission `protection=` value from `packages.xml` (root likely required)
```bash
# Find the permission entry and note the numeric protection value
adb shell su -c "grep -n 'android.permission.WRITE_SETTINGS' /data/system/packages.xml | head -n 1"

# Compare with another permission (pick one you saw in pm list permissions)
adb shell su -c "grep -n 'android.permission.INTERNET' /data/system/packages.xml | head -n 1"

# (optional) list a few permissions + their protection fields
adb shell su -c "grep -n 'protection=' /data/system/packages.xml | head -n 20"
```
Then on your host, decode the number:
- Convert to hex (so you can see the bitmask easily).
- Check whether bits like `0x10` (privileged), `0x40` (appop), `0x80` (pre23), `0x400` (preinstalled) are set.

PowerShell helper:
```powershell
$v = 1218
"$v (0x$('{0:X}' -f $v))"

# test a flag (example: appop)
$v -band 0x40
```

Goal: take one permission line and write out the base level + flags you think it includes.

### Exercise 14: Test a deep link / App Link intent-filter
Pick a package that you think handles web URLs (or use one you pulled in Exercise 3).

1) Fire a VIEW intent with a URL:
```bash
adb shell am start -W \
  -a android.intent.action.VIEW \
  -c android.intent.category.BROWSABLE \
  -c android.intent.category.DEFAULT \
  -d "https://www.example.com/"
```

2) Observe:
- Does it open the app directly, show a chooser, or open the browser?

3) Inspect the app:
```bash
# Look for intent filters / domains in dumpsys output
adb shell "dumpsys package com.example.app | grep -i -E 'autoVerify|intent|domain|host'"

# Open the app details screen (then check "Open by default" / "Opening links")
adb shell am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:com.example.app
```

Goal: understand that intent-filters control **incoming link handling**, not “what domains you can connect to” on the network.

