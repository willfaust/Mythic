import SwiftUI
import os.log

struct ContentView: View {
    @StateObject private var logStore = LogStore.shared
    @State private var jitStatus: JITStatus = .unknown
    @State private var entitlements: EntitlementStatus?
    @State private var showSetupGuide = false

    enum JITStatus {
        case unknown
        case testing
        case available
        case mappingOnly
        case unavailable
    }

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Status header
                statusHeader

                // Entitlement status
                if let ents = entitlements {
                    entitlementBadges(ents)
                }

                Divider()

                // Action buttons
                actionButtons

                Divider()

                // Log console
                logConsole
            }
            .navigationTitle("Mythic")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showSetupGuide = true }) {
                        Image(systemName: "questionmark.circle")
                    }
                }
            }
            .sheet(isPresented: $showSetupGuide) {
                SetupGuideView()
            }
            .onAppear {
                jit_install_trap_handler()
                entitlements = EntitlementStatus.check()
                logEntitlementStatus()
            }
        }
    }

    private var statusHeader: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("JIT Status")
                    .font(.caption)
                    .foregroundColor(.secondary)
                HStack(spacing: 6) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 10, height: 10)
                    Text(statusText)
                        .font(.headline)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                Text("Device")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(deviceInfo)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
    }

    private func entitlementBadges(_ ents: EntitlementStatus) -> some View {
        HStack(spacing: 8) {
            entitlementBadge("JIT", granted: ents.jitAllowed)
            entitlementBadge("Memory+", granted: ents.increasedMemory)
            entitlementBadge("64-bit VA", granted: ents.extendedVA)
            Spacer()
        }
        .padding(.horizontal)
        .padding(.bottom, 8)
    }

    private func entitlementBadge(_ label: String, granted: Bool) -> some View {
        HStack(spacing: 4) {
            Image(systemName: granted ? "checkmark.circle.fill" : "xmark.circle")
                .foregroundColor(granted ? .green : .orange)
                .font(.caption2)
            Text(label)
                .font(.caption2)
                .foregroundColor(granted ? .primary : .secondary)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(granted ? Color.green.opacity(0.1) : Color.orange.opacity(0.1))
        )
    }

    private func logEntitlementStatus() {
        guard let ents = entitlements else { return }
        logStore.log("Checking entitlements...")
        logStore.log("  allow-jit: \(ents.jitAllowed)", level: ents.jitAllowed ? .success : .error)
        logStore.log("  increased-memory-limit: \(ents.increasedMemory)", level: ents.increasedMemory ? .success : .debug)
        logStore.log("  extended-virtual-addressing: \(ents.extendedVA)", level: ents.extendedVA ? .success : .debug)
        if !ents.extendedVA {
            logStore.log("  Tip: Use GetMoreRam to inject extended-virtual-addressing", level: .info)
        }
    }

    private var actionButtons: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 12) {
                Button("Enable JIT") {
                    enableJITViaStikDebug()
                }
                .buttonStyle(.borderedProminent)

                Button("Run Wine") {
                    runWineFullSequence()
                }
                .buttonStyle(.borderedProminent)
                .tint(.orange)

                Button("Test JIT") {
                    runJITTest()
                }
                .buttonStyle(.bordered)

                Button("Test JIT (Alt)") {
                    runJITTestStrategy2()
                }
                .buttonStyle(.bordered)

                Button("Test FEX") {
                    runFEXTest()
                }
                .buttonStyle(.bordered)
                .tint(.purple)

                Button("Start Wineserver") {
                    startWineserver()
                }
                .buttonStyle(.bordered)
                .tint(.green)

                Button("Start Wine") {
                    startWineProcess()
                }
                .buttonStyle(.bordered)
                .tint(.orange)

                Button("Clear Log") {
                    logStore.clear()
                }
                .buttonStyle(.bordered)
                .tint(.red)
            }
            .padding()
        }
    }

    private var logConsole: some View {
        List(logStore.entries.suffix(200)) { entry in
            HStack(alignment: .top, spacing: 8) {
                Text(entry.level.rawValue)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(colorForLevel(entry.level))
                    .frame(width: 30)
                Text(entry.message)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.primary)
            }
            .listRowInsets(EdgeInsets(top: 2, leading: 8, bottom: 2, trailing: 8))
        }
        .listStyle(.plain)
    }

    private var statusColor: Color {
        switch jitStatus {
        case .unknown: return .gray
        case .testing: return .yellow
        case .available: return .green
        case .mappingOnly: return .orange
        case .unavailable: return .red
        }
    }

    private var statusText: String {
        switch jitStatus {
        case .unknown: return "Not tested"
        case .testing: return "Testing..."
        case .available: return "Available"
        case .mappingOnly: return "Needs debugger"
        case .unavailable: return "Unavailable"
        }
    }

    private var deviceInfo: String {
        var sysinfo = utsname()
        uname(&sysinfo)
        let machine = withUnsafePointer(to: &sysinfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }
        return machine
    }

    private func colorForLevel(_ level: LogStore.LogEntry.Level) -> Color {
        switch level {
        case .info: return .blue
        case .success: return .green
        case .error: return .red
        case .debug: return .gray
        }
    }

    private func runJITTest() {
        jitStatus = .testing
        logStore.log("Starting JIT test...")

        DispatchQueue.global(qos: .userInitiated).async {
            let result = jit_test_execute()

            DispatchQueue.main.async {
                switch result {
                case 42:
                    jitStatus = .available
                    logStore.log("JIT is fully functional!", level: .success)
                case -2:
                    jitStatus = .unavailable
                    logStore.log("CS_DEBUGGED not set. Use StikDebug to enable JIT for this app.", level: .error)
                    DispatchQueue.global(qos: .userInitiated).async {
                        let mappingOk = jit_test_mapping()
                        DispatchQueue.main.async {
                            if mappingOk {
                                jitStatus = .mappingOnly
                                logStore.log("Dual mapping works. Enable JIT via StikDebug to unlock execution.", level: .success)
                            }
                        }
                    }
                case -3:
                    jitStatus = .unavailable
                    logStore.log("Fault loop detected — try 'Test JIT (Alt)' for debugger-allocated memory", level: .error)
                default:
                    jitStatus = .unavailable
                    logStore.log("JIT test failed with result: \(result)", level: .error)
                }
            }
        }
    }

    private func runJITTestStrategy2() {
        jitStatus = .testing
        logStore.log("Starting JIT test (Strategy 2: debugger-allocated RX)...")

        DispatchQueue.global(qos: .userInitiated).async {
            let result = jit_test_execute_strategy2()

            DispatchQueue.main.async {
                switch result {
                case 42:
                    jitStatus = .available
                    logStore.log("JIT is fully functional (strategy 2)!", level: .success)
                case -2:
                    jitStatus = .unavailable
                    logStore.log("CS_DEBUGGED not set. Use StikDebug to enable JIT.", level: .error)
                case -3:
                    jitStatus = .unavailable
                    logStore.log("Fault loop — debugger-allocated pages also rejected", level: .error)
                default:
                    jitStatus = .unavailable
                    logStore.log("Strategy 2 failed with result: \(result)", level: .error)
                }
            }
        }
    }

    private func runFEXTest() {
        logStore.log("Starting FEX-Emu integration test...")
        jitStatus = .testing

        // Set up FEX log callback
        fex_set_log_callback { msg in
            if let msg = msg {
                let str = String(cString: msg)
                DispatchQueue.main.async {
                    LogStore.shared.log(str, level: .debug)
                }
            }
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = fex_test_execute()

            DispatchQueue.main.async {
                switch result {
                case 42:
                    jitStatus = .available
                    logStore.log("FEX-Emu test PASSED: x86-64 code returned 42!", level: .success)
                case -1:
                    jitStatus = .unavailable
                    logStore.log("FEX-Emu test FAILED (init/setup error)", level: .error)
                default:
                    jitStatus = .unavailable
                    logStore.log("FEX-Emu test returned \(result)", level: .error)
                }
            }
        }
    }

    private func enableJITViaStikDebug() {
        jitStatus = .testing
        logStore.log("Requesting JIT via StikDebug URL scheme...")

        StikJITHelper.enableJIT { success in
            if success {
                jitStatus = .available
                logStore.log("JIT enabled! Debugger attached.", level: .success)
            } else {
                jitStatus = .unavailable
                logStore.log("Failed to enable JIT via StikDebug", level: .error)
            }
        }
    }

    /// Full sequence: allocate JIT pool, start wineserver, start Wine.
    /// Debugger stays attached during PE loading so mprotect_exec can use BRK
    /// to prepare code pages. Detach happens after Wine finishes + recovery.
    private func runWineFullSequence() {
        guard jit_check_debugged() else {
            logStore.log("JIT not enabled. Press 'Enable JIT' first.", level: .error)
            return
        }

        logStore.log("Running full Wine sequence...")

        // Start a main thread heartbeat to diagnose hang
        var heartbeatCount = 0
        let heartbeat = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { _ in
            heartbeatCount += 1
            os_log("[HEARTBEAT] main thread alive #%d", heartbeatCount)
        }

        // Pause UI flushing — prevents ALL SwiftUI re-renders during Wine execution,
        // so zero main thread hang time accumulates while debugger is attached
        logStore.uiPaused = true

        // Suppress os_log from wineserver — hundreds of messages/sec cause os_log buffer
        // contention that blocks the main thread RunLoop, triggering iOS hang detection
        ws_log_quiet = 1

        DispatchQueue.global(qos: .userInitiated).async {
            // Step 1: Allocate JIT pool (BRK suspends entire process)
            let poolSizeMB = 128
            logStore.log("Allocating \(poolSizeMB)MB JIT pool (BRK will suspend process)...")
            let t0 = CFAbsoluteTimeGetCurrent()
            let pool = StikJITHelper.allocatePool(poolSize: poolSizeMB * 1024 * 1024)
            let elapsed = CFAbsoluteTimeGetCurrent() - t0
            logStore.log("BRK suspension lasted \(String(format: "%.2f", elapsed))s")

            if let pool = pool {
                logStore.log("JIT pool: RX=\(String(format: "%p", Int(bitPattern: pool.rx))), RW=\(String(format: "%p", Int(bitPattern: pool.rw))), size=\(pool.size / 1024 / 1024)MB", level: .success)
                setenv("WINE_IOS_JIT_RX", String(format: "%lx", Int(bitPattern: pool.rx)), 1)
                setenv("WINE_IOS_JIT_RW", String(format: "%lx", Int(bitPattern: pool.rw)), 1)
                setenv("WINE_IOS_JIT_SIZE", String(format: "%lx", pool.size), 1)
            } else {
                logStore.log("JIT pool allocation failed, continuing without it", level: .error)
            }

            // Step 2: Start wineserver
            self.startWineserver()

            // Step 3: Start Wine (debugger still attached for PE loading BRK calls)
            Thread.sleep(forTimeInterval: 2.0)
            self.startWineProcess()

            // Step 4: Wait for Wine to finish instead of fixed timer
            // Poll wine_process_is_running() — it clears when __wine_main returns
            logStore.log("Waiting for Wine to finish PE loading...")
            let maxWait = 30.0  // safety cap
            let pollStart = CFAbsoluteTimeGetCurrent()
            while wine_process_is_running() != 0 {
                Thread.sleep(forTimeInterval: 0.25)
                if CFAbsoluteTimeGetCurrent() - pollStart > maxWait {
                    logStore.log("Wine still running after \(Int(maxWait))s, proceeding with detach", level: .error)
                    break
                }
            }
            let wineElapsed = CFAbsoluteTimeGetCurrent() - pollStart
            logStore.log("Wine finished after \(String(format: "%.1f", wineElapsed))s")

            // Step 5: Resume UI + os_log, give main thread time to recover before detach
            DispatchQueue.main.async {
                ws_log_quiet = 0
                logStore.uiPaused = false
            }
            Thread.sleep(forTimeInterval: 2.0)

            // Step 6: Detach debugger — main thread should have zero accumulated hang time
            logStore.log("Detaching debugger...")
            StikJITHelper.detachDebugger()

            DispatchQueue.main.async { heartbeat.invalidate() }
        }
    }

    private func startWineserver() {
        logStore.log("Starting wineserver...")

        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let winePrefixPath = documentsPath.appendingPathComponent("wine").path

        logStore.log("Wine prefix: \(winePrefixPath)")

        let result = wineserver_start(winePrefixPath)
        if result == 0 {
            logStore.log("Wineserver thread launched successfully", level: .success)
        } else {
            logStore.log("Failed to start wineserver (error: \(result))", level: .error)
        }
    }

    private func startWineProcess() {
        logStore.log("Starting Wine process...")

        if wineserver_is_running() == 0 {
            logStore.log("Wineserver not running! Start it first.", level: .error)
            return
        }

        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let winePrefixPath = documentsPath.appendingPathComponent("wine").path

        // Call synchronously — caller already waited for wineserver to be ready
        let result = wine_process_start(winePrefixPath)
        if result == 0 {
            logStore.log("Wine process thread launched", level: .success)
        } else {
            logStore.log("Failed to start Wine process (error: \(result))", level: .error)
        }
    }

    private func testDualMapping() {
        logStore.log("Testing dual-mapped memory properties...")

        DispatchQueue.global(qos: .userInitiated).async {
            testDualMappingImpl()
        }
    }

    private func testDualMappingImpl() {
        logStore.log("Creating 64KB dual-mapped region...")

        guard let region = jit_region_create(65536) else {
            logStore.log("Failed to create dual-mapped region", level: .error)
            return
        }

        let rwPtr = jit_region_rw_ptr(region)
        let rxPtr = jit_region_rx_ptr(region)
        let size = jit_region_size(region)

        logStore.log("Region created: size=\(size)")
        logStore.log("  RW ptr: \(String(format: "%p", Int(bitPattern: rwPtr)))")
        logStore.log("  RX ptr: \(String(format: "%p", Int(bitPattern: rxPtr)))")

        // Test 1: Write to RW, verify readable from RX
        let testPattern: UInt32 = 0xDEADBEEF
        rwPtr?.assumingMemoryBound(to: UInt32.self).pointee = testPattern
        let readBack = rxPtr?.assumingMemoryBound(to: UInt32.self).pointee

        if readBack == testPattern {
            logStore.log("Dual mapping verified: write to RW visible from RX", level: .success)
        } else {
            logStore.log("Dual mapping FAILED: wrote \(String(format: "0x%X", testPattern)), read \(String(format: "0x%X", readBack ?? 0))", level: .error)
        }

        // Test 2: Verify RW and RX are at different virtual addresses
        if rwPtr != rxPtr {
            logStore.log("Distinct virtual addresses confirmed (RW != RX)", level: .success)
        } else {
            logStore.log("WARNING: RW and RX are at the same address", level: .error)
        }

        jit_region_destroy(region)
        logStore.log("Region destroyed. Dual mapping test complete.")
    }
}

struct SetupGuideView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            List {
                Section("Requirements") {
                    guideRow(
                        icon: "cpu",
                        title: "JIT Compilation",
                        detail: "Required for x86 code translation. On iOS 26, StikDebug must stay attached — assign the 'universal' or 'MeloNX' JIT script to Mythic in StikDebug."
                    )
                    guideRow(
                        icon: "memorychip",
                        title: "Increased Memory Limit",
                        detail: "Raises the Jetsam memory threshold. Included in the app entitlements. If not detected, use GetMoreRam to inject it."
                    )
                    guideRow(
                        icon: "arrow.up.left.and.arrow.down.right",
                        title: "Extended Virtual Addressing",
                        detail: "Expands virtual address space to ~64GB. Required for large games. Must be injected via GetMoreRam (free accounts can't provision this)."
                    )
                }

                Section("Setup Steps") {
                    stepRow(number: 1, text: "Install Mythic via SideStore or Xcode")
                    stepRow(number: 2, text: "Install GetMoreRam and run it to inject memory entitlements into your App ID")
                    stepRow(number: 3, text: "Reinstall Mythic with the same IPA to apply injected entitlements")
                    stepRow(number: 4, text: "In StikDebug, assign the 'universal' JIT script to Mythic and launch it")
                    stepRow(number: 5, text: "Launch Mythic and tap 'Test JIT' to verify")
                }

                Section("About") {
                    Text("Mythic is a proof-of-concept for running x86 Windows games on iOS using FEX-Emu, Wine, and Metal-based graphics translation.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .navigationTitle("Setup Guide")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func guideRow(icon: String, title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundColor(.accentColor)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline).fontWeight(.medium)
                Text(detail).font(.caption).foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }

    private func stepRow(number: Int, text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(number)")
                .font(.caption).fontWeight(.bold)
                .foregroundColor(.white)
                .frame(width: 22, height: 22)
                .background(Circle().fill(Color.accentColor))
            Text(text)
                .font(.subheadline)
        }
        .padding(.vertical, 2)
    }
}
