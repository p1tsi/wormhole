# Wormhole (Work in Progress)

**Wormhole** is a wrapper for [Frida](https://github.com/frida), designed to simplify iOS/macOS application analysis for penetration testers and reverse engineers.

It enables dynamic analysis and comprehensive data extraction from iOS apps, without requiring deep knowledge of Frida or manual execution of multiple commands.

---

## Features

- Bypass SSL pinning

- Bypass jailbreak detection

- Extract unencrypted IPAs

- Hook functions by class

- Modular and customizable hook system

- Retrieve static app metadata (e.g., entitlements, `Info.plist`)

- Dump Keychain contents

- List open file descriptors (vnode and socket)

- Dump Objective-C in-memory objects

- ... and more

> **Note:** Wormhole is under active (though somewhat irregular) development. Some features, such as network or SQLite hooking, may be incomplete or produce imprecise results.

---

## Architecture

Wormhole consists of three main components:

-  **`wormhole-core`**: The main controller, responsible for coordinating analysis tasks.

-  **`wormhole-agent`**: A Frida-based JavaScript agent injected into the target process for runtime instrumentation.

-  **`wormhole-gui`**: A graphical interface to enhance usability and interaction.

---

## Getting Started

Build & run the project:

```bash
make
make  run
```

Start only one component:
```bash
make  run-server
```
```bash
make  run-gui
```

Run analysis scripts:

```bash
make  run-trace  # For runtime tracing only

make  run-dump  # For IPA dumping only

```

```bash
make  build-agent-ios  # For runtime tracing only

make  build-agent-macos  # For IPA dumping only

make reinstall-core     # For rebuilding the core

```
---

## Credits

Portions of the `wormhole-agent` and `wormhole-gui` are adapted from [grapefruit](https://github.com/ChiChou/grapefruit) by [ChiChou](https://github.com/ChiChou).