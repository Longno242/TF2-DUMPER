# tf2_dumper

Windows console tool that attaches to a running Team Fortress 2 process, finds `client.dll`, and dumps **networked client netvars** (Source 1 `ClientClass` → `RecvTable` → `RecvProp`): hierarchical names and entity-relative hex offsets.

Build **x64** for the 64-bit client (`tf_win64.exe`) and **Win32** for the legacy 32-bit client (`hl2.exe`). The architecture of the dumper must match the game’s architecture.

## Requirements

- Windows  
- CMake 3.16+  
- MSVC (Visual Studio with C++ workload) or another CMake-supported C++ toolchain  

## Build

Open a **x64 Native Tools** or **x86 Native Tools** command prompt (or any shell where `cmake` finds the right compiler).

**64-bit TF2 (`tf_win64.exe`):**

```bat
cmake -S . -B build_x64 -A x64
cmake --build build_x64 --config Release
```

Output: `build_x64\Release\tf2_dumper.exe`

**32-bit TF2 (`hl2.exe`):**

```bat
cmake -S . -B build -A Win32
cmake --build build --config Release
```

Output: `build\Release\tf2_dumper.exe`

## Run

1. Start TF2 and reach at least the main menu so `client.dll` is loaded.  
2. Run the dumper **matching** your game (x64 vs Win32). Run as **Administrator** if `OpenProcess` fails.

```bat
tf2_dumper.exe tf_win64.exe --out netvars.txt
```

Default process name is `hl2.exe` if you omit the first argument.

With `--out`, status messages go to the console; the **full netvar list** is written to the file. If you only see `PID` and `client.dll` on the console, open the output file — it is created in your **current working directory** (e.g. `C:\Users\You\netvars.txt` if you ran the command from `C:\Users\You`).

### Options

| Option | Description |
|--------|-------------|
| `--out <path>` | Write the dump to a file. |
| `--head 0x…` | Skip auto-scan; use this `ClientClass*` pointer (debugging / failed auto-detect). |
| `--pattern "<hex pattern>"` | Scan the first 16 MiB of `client.dll` for an IDA-style pattern (`?` = wildcard); then exit. |
| `-h`, `--help` | Short usage. |

Auto-detection of the `ClientClass` list can take a while; the console prints progress when using `--out`.

## Output format

Lines look like:

```text
// ClientClass: …  recv: DT_SomeClass  id=…  ptr=0x…

DT_SomeClass.someProp.nested = 0x1234
```

Offsets are **entity-relative** (RecvTable layout), not raw pointers.

## Troubleshooting

- **`client.dll not loaded`** — Wrong process name, game not running, or **wrong dumper bitness** (use x64 for `tf_win64.exe`).  
- **`Could not locate ClientClass list head`** — Try again after the game fully loads, or supply `--head` from your own analysis.  
- **Offsets look wrong after a game update** — `src/source_layout.h` may need adjustment for MSVC layout changes (rare).

## Disclaimer

This tool reads memory from a live game process. That may violate game or platform terms and can interact with anti-cheat. Use only on accounts and environments where you are allowed to do so. This project is for education and interoperability research.
