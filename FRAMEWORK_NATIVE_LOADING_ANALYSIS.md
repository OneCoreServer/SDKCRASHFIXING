# NewBlackBox vs reference_sdk: Native Library Loading Analysis

## 1) Loading model comparison

### reference_sdk
- Native core class statically loads core JNI lib first (`System.loadLibrary(...)`).
- Then it loads target loader library from app files path (`files/loader/<target>.so`) in static init.
- Native hook chain (`init`, `enableIO`, `addIORule`, `hideXposed`) is called from framework lifecycle (app thread / IOCore flow).

### NewBlackBox (current app integration)
- App currently tries to prepare `files/loader/libbgmi.so` before launch from `ApkEnv.tryAddLoader`.
- It attempts target sync + static class load + native init methods via reflection.
- It then may copy to container `nativeLibraryDir` as best-effort, but primary framework-compatible path remains `files/loader/<target>.so`.

## 2) Where native initialization happens in NewBlackBox app lifecycle
- Start Game button calls `do_Lib_And_Run(...)` in `MainActivity`.
- `do_Lib_And_Run(...)` validates `files/loader/libbgmi.so` exists and then calls `ApkEnv.tryAddLoader(...)`.
- In `tryAddLoader(...)`, framework prep occurs before launch:
  1. sync native target field
  2. force native core class static load
  3. invoke native init/hide methods where available
  4. resolve loader path and optional copy

## 3) ClassLoader/linker/sandbox considerations
- In virtualized frameworks, target app process and host process are separated.
- `System.load(...)` in host process alone may not affect virtual app process hooks unless framework native core executes inside target process lifecycle.
- If custom classloader is used by virtual engine, native core class must be loaded in the same process/classloader context where hooks are needed.

## 4) Safe integration approach (framework-aligned)
1. Keep canonical loader at `files/loader/libbgmi.so` (or exact target expected by core class).
2. Ensure native core class static init runs in virtualized app process lifecycle (not only host UI thread).
3. Trigger framework-provided native init methods (`init`, `enableIO`, `addIORule`, `hideXposed`) through official lifecycle points where available.
4. Avoid relying only on direct copy to `nativeLibraryDir`; use framework loader path convention first.
5. Keep reflection only as compatibility fallback for obfuscated variants.

## 5) ABI + path resolution checklist
- ABI must match virtualized process ABI (here arm64-v8a).
- Confirm `Saved.zip` extracted file actually lands at:
  - `<host files dir>/loader/libbgmi.so`
- Confirm no wrong nesting like `loader/loader/libbgmi.so`.
- Confirm file permissions: readable/executable.

## 6) Timing requirements
- Loader file must exist before virtual app process starts.
- Framework native core static init should run before target game `libUE4.so` / target lib reaches hook point.
- If hook setup is too late (post-launch), effects may be absent even if `.so` loads successfully.

## 7) Logging/debug points (safe)
Add/verify logs at:
- Download/extract complete + final absolute path of loader file.
- Before launch: loader path existence + file size + ABI folder.
- Native core sync result: class name + field written.
- Native core static init attempt success/failure.
- Native init/hide method invocation success/failure.
- Virtual process startup and package launch timestamp.
- If available in framework native side: `JNI_OnLoad`, `init`, `enableIO`, target-lib-detected events.

## Practical next implementation step
- Move/duplicate native-core init trigger to the earliest virtual process lifecycle callback provided by NewBlackBox framework (e.g., virtual app bind/start callback), not only from host activity path.
