import UIKit

/// Helper to enable JIT via StikDebug/StikJIT URL scheme.
/// Opens StikDebug with an embedded script, polls for CS_DEBUGGED,
/// then allocates JIT memory and detaches the debugger.
enum StikJITHelper {

    /// The JIT script. Edit mythic-jit.js, then run:
    ///   base64 -i app/Mythic/mythic-jit.js | tr -d '\n' | pbcopy
    /// and paste below. TODO: load from bundle resource instead.
    private static let scriptBase64 = "Ly8gTXl0aGljIEpJVCBTY3JpcHQgZm9yIFN0aWtEZWJ1ZwovLyBIYW5kbGVzIEJSSyAjMHhmMDBkICh1bml2ZXJzYWwgcHJvdG9jb2wpIHdpdGggeDE2LWJhc2VkIGNvbW1hbmQgZGlzcGF0Y2gKLy8gQWR2YW5jZXMgUEMgcGFzdCBBTEwgQlJLIGluc3RydWN0aW9ucyB0byBwcmV2ZW50IGluZmluaXRlIGxvb3BzCgpmdW5jdGlvbiBsaXR0bGVFbmRpYW5IZXhTdHJpbmdUb051bWJlcihoZXhTdHIpIHsKICAgIGNvbnN0IGJ5dGVzID0gW107CiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGhleFN0ci5sZW5ndGg7IGkgKz0gMikgewogICAgICAgIGJ5dGVzLnB1c2gocGFyc2VJbnQoaGV4U3RyLnN1YnN0cihpLCAyKSwgMTYpKTsKICAgIH0KICAgIGxldCBudW0gPSAwbjsKICAgIGZvciAobGV0IGkgPSA3OyBpID49IDA7IGktLSkgewogICAgICAgIG51bSA9IChudW0gPDwgOG4pIHwgQmlnSW50KGJ5dGVzW2ldIHx8IDApOwogICAgfQogICAgcmV0dXJuIG51bTsKfQoKZnVuY3Rpb24gbnVtYmVyVG9MaXR0bGVFbmRpYW5IZXhTdHJpbmcobnVtKSB7CiAgICBjb25zdCBieXRlcyA9IFtdOwogICAgZm9yIChsZXQgaSA9IDA7IGkgPCA4OyBpKyspIHsKICAgICAgICBieXRlcy5wdXNoKE51bWJlcihudW0gJiAweEZGbikpOwogICAgICAgIG51bSA+Pj0gOG47CiAgICB9CiAgICByZXR1cm4gYnl0ZXMubWFwKGIgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSkuam9pbignJyk7Cn0KCmZ1bmN0aW9uIGxpdHRsZUVuZGlhbkhleFRvVTMyKGhleFN0cikgewogICAgcmV0dXJuIHBhcnNlSW50KGhleFN0ci5tYXRjaCgvLi4vZykucmV2ZXJzZSgpLmpvaW4oJycpLCAxNik7Cn0KCmZ1bmN0aW9uIGV4dHJhY3RCcmtJbW1lZGlhdGUodTMyKSB7CiAgICByZXR1cm4gKHUzMiA+PiA1KSAmIDB4RkZGRjsKfQoKbGV0IHBpZCA9IGdldF9waWQoKTsKbG9nKGBNeXRoaWMgSklUOiBwaWQgPSAke3BpZH1gKTsKbGV0IGF0dGFjaFJlc3BvbnNlID0gc2VuZF9jb21tYW5kKGB2QXR0YWNoOyR7cGlkLnRvU3RyaW5nKDE2KX1gKTsKbG9nKGBNeXRoaWMgSklUOiBhdHRhY2hlZCA9ICR7YXR0YWNoUmVzcG9uc2V9YCk7CgpsZXQgZGV0YWNoZWQgPSBmYWxzZTsKCndoaWxlICghZGV0YWNoZWQpIHsKICAgIGxldCBicmtSZXNwb25zZSA9IHNlbmRfY29tbWFuZChgY2ApOwoKICAgIGxldCB0aWRNYXRjaCA9IC9UWzAtOWEtZl0rdGhyZWFkOig/PHRpZD5bMC05YS1mXSspOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBsZXQgdGlkID0gdGlkTWF0Y2ggPyB0aWRNYXRjaC5ncm91cHNbJ3RpZCddIDogbnVsbDsKICAgIGxldCBwY01hdGNoID0gLzIwOig/PHJlZz5bMC05YS1mXXsxNn0pOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBsZXQgcGMgPSBwY01hdGNoID8gcGNNYXRjaC5ncm91cHNbJ3JlZyddIDogbnVsbDsKICAgIGxldCB4MTZNYXRjaCA9IC8xMDooPzxyZWc+WzAtOWEtZl17MTZ9KTsvLmV4ZWMoYnJrUmVzcG9uc2UpOwogICAgbGV0IHgxNiA9IHgxNk1hdGNoID8geDE2TWF0Y2guZ3JvdXBzWydyZWcnXSA6IG51bGw7CgogICAgaWYgKCF0aWQgfHwgIXBjIHx8ICF4MTYpIHsKICAgICAgICBsb2coYE15dGhpYyBKSVQ6IGZhaWxlZCB0byBwYXJzZSwgY29udGludWluZ2ApOwogICAgICAgIGNvbnRpbnVlOwogICAgfQoKICAgIGxldCBwY051bSA9IGxpdHRsZUVuZGlhbkhleFN0cmluZ1RvTnVtYmVyKHBjKTsKCiAgICBsZXQgaW5zdHJIZXggPSBzZW5kX2NvbW1hbmQoYG0ke3BjTnVtLnRvU3RyaW5nKDE2KX0sNGApOwogICAgbGV0IGluc3RyVTMyID0gbGl0dGxlRW5kaWFuSGV4VG9VMzIoaW5zdHJIZXgpOwogICAgbGV0IGJya0ltbSA9IGV4dHJhY3RCcmtJbW1lZGlhdGUoaW5zdHJVMzIpOwoKICAgIC8vIEFMV0FZUyBhZHZhbmNlIFBDIHBhc3QgQlJLIHRvIHByZXZlbnQgaW5maW5pdGUgbG9vcAogICAgbGV0IHBjUGx1czQgPSBudW1iZXJUb0xpdHRsZUVuZGlhbkhleFN0cmluZyhwY051bSArIDRuKTsKICAgIHNlbmRfY29tbWFuZChgUDIwPSR7cGNQbHVzNH07dGhyZWFkOiR7dGlkfTtgKTsKCiAgICAvLyBTa2lwIHVua25vd24gQlJLIGltbWVkaWF0ZXMgKFBDIGFscmVhZHkgYWR2YW5jZWQpCiAgICBpZiAoYnJrSW1tICE9PSAweGYwMGQgJiYgYnJrSW1tICE9PSAweDY5KSB7CiAgICAgICAgLy8gU2V0IHgwPTAgKGZhaWx1cmUvc2tpcCBpbmRpY2F0b3IpIHNvIGFwcCdzIFNJR1RSQVAgZmFsbGJhY2sgd29ya3MKICAgICAgICBzZW5kX2NvbW1hbmQoYFAwPSR7bnVtYmVyVG9MaXR0bGVFbmRpYW5IZXhTdHJpbmcoMG4pfTt0aHJlYWQ6JHt0aWR9O2ApOwogICAgICAgIGNvbnRpbnVlOwogICAgfQoKICAgIGxvZyhgTXl0aGljIEpJVDogQlJLICMweCR7YnJrSW1tLnRvU3RyaW5nKDE2KX1gKTsKCiAgICAvLyBQYXJzZSB4MCBhbmQgeDEKICAgIGxldCB4ME1hdGNoID0gLzAwOig/PHJlZz5bMC05YS1mXXsxNn0pOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBsZXQgeDFNYXRjaCA9IC8wMTooPzxyZWc+WzAtOWEtZl17MTZ9KTsvLmV4ZWMoYnJrUmVzcG9uc2UpOwogICAgbGV0IHgwID0geDBNYXRjaCA/IGxpdHRsZUVuZGlhbkhleFN0cmluZ1RvTnVtYmVyKHgwTWF0Y2guZ3JvdXBzWydyZWcnXSkgOiAwbjsKICAgIGxldCB4MSA9IHgxTWF0Y2ggPyBsaXR0bGVFbmRpYW5IZXhTdHJpbmdUb051bWJlcih4MU1hdGNoLmdyb3Vwc1sncmVnJ10pIDogMG47CiAgICBsZXQgeDE2TnVtID0gbGl0dGxlRW5kaWFuSGV4U3RyaW5nVG9OdW1iZXIoeDE2KTsKCiAgICBpZiAoYnJrSW1tID09PSAweGYwMGQpIHsKICAgICAgICBsb2coYE15dGhpYyBKSVQ6IHgxNiA9ICR7eDE2TnVtfWApOwoKICAgICAgICBpZiAoeDE2TnVtID09PSAwbikgewogICAgICAgICAgICAvLyBDTURfREVUQUNICiAgICAgICAgICAgIGxvZyhgTXl0aGljIEpJVDogZGV0YWNoYCk7CiAgICAgICAgICAgIHNlbmRfY29tbWFuZChgRGApOwogICAgICAgICAgICBkZXRhY2hlZCA9IHRydWU7CgogICAgICAgIH0gZWxzZSBpZiAoeDE2TnVtID09PSAxbikgewogICAgICAgICAgICAvLyBDTURfUFJFUEFSRV9SRUdJT04KICAgICAgICAgICAgbG9nKGBNeXRoaWMgSklUOiBwcmVwYXJlIGFkZHI9MHgke3gwLnRvU3RyaW5nKDE2KX0gc2l6ZT0weCR7eDEudG9TdHJpbmcoMTYpfWApOwoKICAgICAgICAgICAgbGV0IGFkZHIgPSB4MDsKICAgICAgICAgICAgaWYgKHgwID09PSAwbiAmJiB4MSAhPT0gMG4pIHsKICAgICAgICAgICAgICAgIGxldCBhbGxvY1Jlc3AgPSBzZW5kX2NvbW1hbmQoYF9NJHt4MS50b1N0cmluZygxNil9LHJ4YCk7CiAgICAgICAgICAgICAgICBpZiAoYWxsb2NSZXNwICYmIGFsbG9jUmVzcC5sZW5ndGggPiAwKSB7CiAgICAgICAgICAgICAgICAgICAgYWRkciA9IEJpZ0ludChgMHgke2FsbG9jUmVzcH1gKTsKICAgICAgICAgICAgICAgICAgICBsb2coYE15dGhpYyBKSVQ6IGFsbG9jYXRlZCBhdCAweCR7YWRkci50b1N0cmluZygxNil9YCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIGlmIChhZGRyICE9PSAwbiAmJiB4MSAhPT0gMG4pIHsKICAgICAgICAgICAgICAgIGxldCBwcmVwUmVzcCA9IHByZXBhcmVfbWVtb3J5X3JlZ2lvbihhZGRyLCB4MSk7CiAgICAgICAgICAgICAgICBsb2coYE15dGhpYyBKSVQ6IHByZXBhcmVkID0gJHtwcmVwUmVzcH1gKTsKICAgICAgICAgICAgfQoKICAgICAgICAgICAgc2VuZF9jb21tYW5kKGBQMD0ke251bWJlclRvTGl0dGxlRW5kaWFuSGV4U3RyaW5nKGFkZHIpfTt0aHJlYWQ6JHt0aWR9O2ApOwoKICAgICAgICB9IGVsc2UgaWYgKHgxNk51bSA9PT0gM24pIHsKICAgICAgICAgICAgLy8gQ01EX01BUF9QQUdFX1pFUk86IE1hcCBhIHBhZ2UgYXQgYWRkcmVzcyAwIHdpdGggVEVCIGRhdGEuCiAgICAgICAgICAgIC8vIHgwID0gVEVCIGFkZHJlc3MsIHgxID0gc2l6ZSAoMHg0MDAwID0gMTZLQiBpT1MgcGFnZSkKICAgICAgICAgICAgLy8gVGhlIGFwcCBjYW4ndCBtYXAgcGFnZSAwIGl0c2VsZiAoa2VybmVsIHJlZnVzZXMpLiBUaGUgZGVidWdnZXIKICAgICAgICAgICAgLy8gbWF5IGhhdmUgZGlmZmVyZW50IHByaXZpbGVnZXMgdG8gY3JlYXRlIHRoaXMgbWFwcGluZy4KICAgICAgICAgICAgbG9nKGBNeXRoaWMgSklUOiBtYXAgcGFnZSB6ZXJvLCBURUI9MHgke3gwLnRvU3RyaW5nKDE2KX0gc2l6ZT0weCR7eDEudG9TdHJpbmcoMTYpfWApOwoKICAgICAgICAgICAgbGV0IHN1Y2Nlc3MgPSAwbjsKCiAgICAgICAgICAgIC8vIFRyeSBhbGxvY2F0aW5nIFJXIG1lbW9yeSBhdCBhZGRyZXNzIDAgdmlhIF9NIHdpdGggZml4ZWQgYWRkcmVzcwogICAgICAgICAgICAvLyBTdGlrRGVidWcncyBfTSBjb21tYW5kOiBfTTxzaXplPiw8cGVybXM+IOKAlCBidXQgZG9lc24ndCBzdXBwb3J0IGZpeGVkIGFkZHIKICAgICAgICAgICAgLy8gVHJ5IEdEQiBtZW1vcnkgYWxsb2NhdGlvbjogbW1hcCB2aWEgdGhlIGRlYnVnZ2VyJ3MgdGFzayBwb3J0CiAgICAgICAgICAgIC8vIFVzZSB2Q29udCBvciBkaXJlY3QgTWFjaCBjYWxscyBpZiBhdmFpbGFibGUKCiAgICAgICAgICAgIC8vIEFwcHJvYWNoIDE6IFRyeSB3cml0aW5nIFRFQiBkYXRhIHRvIGFkZHJlc3MgMCBkaXJlY3RseS4KICAgICAgICAgICAgLy8gSWYgdGhlIGhhcmR3YXJlIHplcm8gcGFnZSBpcyB3cml0YWJsZSB2aWEgdGhlIGRlYnVnZ2VyLCB0aGlzIHdvcmtzLgogICAgICAgICAgICBpZiAoeDAgIT09IDBuICYmIHgxICE9PSAwbikgewogICAgICAgICAgICAgICAgLy8gUmVhZCBURUIgZGF0YSBmcm9tIHRoZSBhcHAncyBtZW1vcnkKICAgICAgICAgICAgICAgIGxldCB0ZWJQYWdlID0geDAgJiB+MHgzRkZGbjsgIC8vIGFsaWduIHRvIDE2S0IgcGFnZQogICAgICAgICAgICAgICAgbGV0IHRlYk9mZiA9IHgwIC0gdGViUGFnZTsKCiAgICAgICAgICAgICAgICAvLyBUcnkgdG8gd3JpdGUgVEVCIGRhdGEgYXQgYWRkcmVzcyAwIHZpYSBHREIgTSBjb21tYW5kCiAgICAgICAgICAgICAgICAvLyBSZWFkIDI1NiBieXRlcyBmcm9tIFRFQiAoZW5vdWdoIGZvciBQRUIgcG9pbnRlciBhdCBvZmZzZXQgMHg2MCkKICAgICAgICAgICAgICAgIGxldCB0ZWJEYXRhID0gc2VuZF9jb21tYW5kKGBtJHt4MC50b1N0cmluZygxNil9LDEwMGApOwogICAgICAgICAgICAgICAgaWYgKHRlYkRhdGEgJiYgdGViRGF0YS5sZW5ndGggPiAwKSB7CiAgICAgICAgICAgICAgICAgICAgLy8gV3JpdGUgaXQgdG8gYWRkcmVzcyAwK3RlYk9mZgogICAgICAgICAgICAgICAgICAgIGxldCB3cml0ZVJlc3AgPSBzZW5kX2NvbW1hbmQoYE0ke3RlYk9mZi50b1N0cmluZygxNil9LCR7KHRlYkRhdGEubGVuZ3RoLzIpLnRvU3RyaW5nKDE2KX06JHt0ZWJEYXRhfWApOwogICAgICAgICAgICAgICAgICAgIGxvZyhgTXl0aGljIEpJVDogd3JpdGUgVEVCIHRvIHBhZ2UwIG9mZnNldCAweCR7dGViT2ZmLnRvU3RyaW5nKDE2KX06ICR7d3JpdGVSZXNwfWApOwogICAgICAgICAgICAgICAgICAgIGlmICh3cml0ZVJlc3AgPT09ICdPSycpIHsKICAgICAgICAgICAgICAgICAgICAgICAgc3VjY2VzcyA9IDFuOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgc2VuZF9jb21tYW5kKGBQMD0ke251bWJlclRvTGl0dGxlRW5kaWFuSGV4U3RyaW5nKHN1Y2Nlc3MpfTt0aHJlYWQ6JHt0aWR9O2ApOwogICAgICAgIH0KCiAgICB9IGVsc2UgaWYgKGJya0ltbSA9PT0gMHg2OSkgewogICAgICAgIC8vIExlZ2FjeSBwcm90b2NvbAogICAgICAgIGxvZyhgTXl0aGljIEpJVDogbGVnYWN5IEJSSyAweDY5LCB4MD0weCR7eDAudG9TdHJpbmcoMTYpfWApOwogICAgICAgIGlmICh4MCAhPT0gMG4pIHsKICAgICAgICAgICAgcHJlcGFyZV9tZW1vcnlfcmVnaW9uKHgwLCB4MCk7CiAgICAgICAgfQogICAgICAgIHNlbmRfY29tbWFuZChgUDA9JHtudW1iZXJUb0xpdHRsZUVuZGlhbkhleFN0cmluZyh4MCl9O3RocmVhZDoke3RpZH07YCk7CiAgICB9Cn0K"

    /// Load script from mythic-jit.js file next to the binary (development convenience).
    /// Falls back to the embedded base64 above for release builds.
    private static var resolvedScriptBase64: String {
        // Try loading from bundle first (if added to Copy Bundle Resources)
        if let url = Bundle.main.url(forResource: "mythic-jit", withExtension: "js"),
           let data = try? Data(contentsOf: url) {
            return data.base64EncodedString()
        }
        return scriptBase64
    }

    /// Check if StikDebug or StikJIT is available by trying to open their URL.
    static var isAvailable: Bool {
        guard let url = URL(string: "stikjit://enable-jit") else { return false }
        return UIApplication.shared.canOpenURL(url)
    }

    /// Open StikDebug with our JIT script embedded in the URL.
    /// StikDebug will attach to our process and run the script.
    static func enableJIT(completion: @escaping (Bool) -> Void) {
        let bundleId = Bundle.main.bundleIdentifier ?? "com.mythic.emulator"

        // Build the URL with script data
        let scriptData = resolvedScriptBase64.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        let urlString = "stikjit://enable-jit?bundle-id=\(bundleId)&script-data=\(scriptData)"

        guard let url = URL(string: urlString) else {
            LogStore.shared.log("Failed to build StikJIT URL", level: .error)
            completion(false)
            return
        }

        LogStore.shared.log("Opening StikDebug to enable JIT...")

        UIApplication.shared.open(url, options: [:]) { success in
            if !success {
                LogStore.shared.log("Failed to open StikDebug. Is it installed?", level: .error)
                completion(false)
                return
            }

            // Poll for CS_DEBUGGED flag
            pollForJIT(completion: completion)
        }
    }

    /// Poll every 0.5s until CS_DEBUGGED is set, then call completion.
    private static func pollForJIT(completion: @escaping (Bool) -> Void) {
        Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { timer in
            if jit_check_debugged() {
                timer.invalidate()
                LogStore.shared.log("JIT enabled! (CS_DEBUGGED set)", level: .success)
                completion(true)
            }
        }
    }

    /// Allocate a JIT memory pool via BRK #0xf00d, then detach the debugger.
    /// Call this after CS_DEBUGGED is confirmed.
    /// Returns the allocated RX base address and RW mapping, or nil on failure.
    static func allocateAndDetach(poolSize: Int = 128 * 1024 * 1024) -> (rx: UnsafeMutableRawPointer, rw: UnsafeMutableRawPointer, size: Int)? {
        guard let result = allocatePool(poolSize: poolSize) else { return nil }
        // Don't detach yet — Wine needs the debugger to prepare PE DLL code pages.
        // Detach will happen later via detachDebugger().
        return result
    }

    /// Allocate a JIT memory pool via BRK #0xf00d WITHOUT detaching the debugger.
    /// The debugger stays attached so Wine can use BRK to prepare PE code pages.
    static func allocatePool(poolSize: Int = 128 * 1024 * 1024) -> (rx: UnsafeMutableRawPointer, rw: UnsafeMutableRawPointer, size: Int)? {
        LogStore.shared.log("Allocating \(poolSize / 1024 / 1024)MB JIT pool via debugger...")

        // iOS-Mythic: FEX's dispatcher emit has a position-dependent encoding
        // bug — only works when the JIT pool lands at a high enough address
        // (empirically ≥ 0x119000000, so dispatcher at +0x7ffc130 has top byte
        // 0x12). When iOS allocates 0x114-0x117xxx the dispatcher's literal-
        // pool fixups silently break and execution branches to zero memory
        // before the first compiled block runs. Pre-claim ~96MB of low address
        // space to push the next ANYWHERE allocation up.
        //
        // We keep these allocations alive for the lifetime of the process —
        // freeing them could let iOS reuse them and cause aliasing issues.
        var pinChunks: [vm_address_t] = []
        let chunkSize = 16 * 1024 * 1024  // 16 MB per chunk
        let numChunks = 6                  // 96 MB total
        for i in 0..<numChunks {
            var addr: vm_address_t = 0
            let kr = vm_allocate(mach_task_self_, &addr, vm_size_t(chunkSize), VM_FLAGS_ANYWHERE)
            if kr == KERN_SUCCESS {
                pinChunks.append(addr)
                LogStore.shared.log(String(format: "JIT-pool pin chunk %d at 0x%lx (16MB)", i, Int(addr)))
            } else {
                LogStore.shared.log("JIT-pool pin chunk \(i) FAILED kr=\(kr)", level: .error)
                break
            }
        }

        // Ask debugger to allocate RX pages (x0=0 triggers _M allocation).
        // With pin chunks claimed, this should land at a higher address.
        guard let rxPtr = jit26_prepare_region(nil, poolSize), rxPtr != UnsafeMutableRawPointer(bitPattern: 0) else {
            LogStore.shared.log("Debugger failed to allocate RX memory", level: .error)
            return nil
        }

        let rxAddr = Int(bitPattern: rxPtr)
        LogStore.shared.log("RX pool at \(String(format: "%p", rxAddr))")
        // FEX has a position-dependent emit bug at low pool addresses (mode A:
        // dispatcher branches to zero memory before block 0 ever runs). The
        // signal_arm64_ios.c init_syscall_frame applies a runtime patch that
        // fixes the higher-address mode B (SpillStaticRegs literal-pool
        // corruption), so any pool ≥ 0x119000000 should now work. Below that,
        // fast-fail to save Wine-init time.
        let goodLow: Int = 0x119000000
        if rxAddr < goodLow {
            LogStore.shared.log("BAD POOL (mode A): 0x\(String(rxAddr, radix: 16)) < 0x\(String(goodLow, radix: 16)). Killing in 10s — please relaunch.", level: .error)
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 10) {
                LogStore.shared.log("BAD POOL — exiting now. Relaunch the app.", level: .error)
                exit(0)
            }
            return nil
        }

        // Create RW mapping via vm_remap
        var rwAddr: vm_address_t = 0
        var curProt: vm_prot_t = 0
        var maxProt: vm_prot_t = 0

        let kr1 = vm_remap(
            mach_task_self_,
            &rwAddr,
            vm_size_t(poolSize),
            0,
            VM_FLAGS_ANYWHERE,
            mach_task_self_,
            vm_address_t(bitPattern: rxPtr),
            0, // copy = false
            &curProt,
            &maxProt,
            VM_INHERIT_NONE
        )

        guard kr1 == KERN_SUCCESS else {
            LogStore.shared.log("vm_remap failed: \(kr1)", level: .error)
            return nil
        }

        // Set RW protection
        let kr2 = vm_protect(mach_task_self_, rwAddr, vm_size_t(poolSize), 0, VM_PROT_READ | VM_PROT_WRITE)
        guard kr2 == KERN_SUCCESS else {
            LogStore.shared.log("vm_protect(RW) failed: \(kr2)", level: .error)
            vm_deallocate(mach_task_self_, rwAddr, vm_size_t(poolSize))
            return nil
        }

        let rwPtr = UnsafeMutableRawPointer(bitPattern: rwAddr)!
        LogStore.shared.log("RW mapping at \(String(format: "%p", Int(bitPattern: rwPtr)))")
        LogStore.shared.log("JIT pool ready (debugger still attached).", level: .success)

        return (rx: rxPtr, rw: rwPtr, size: poolSize)
    }

    /// Detach the debugger. Call this after Wine is done loading PE DLLs.
    static func detachDebugger() {
        LogStore.shared.log("Detaching debugger...")
        jit26_detach()
        LogStore.shared.log("Debugger detached.", level: .success)
    }
}
