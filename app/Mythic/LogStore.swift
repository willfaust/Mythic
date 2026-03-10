import Foundation
import SwiftUI

final class LogStore: ObservableObject {
    static let shared = LogStore()

    @Published var entries: [LogEntry] = []

    private let logFileURL: URL
    private let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    // Batching: accumulate entries and flush to UI periodically
    private var pendingEntries: [LogEntry] = []
    private let pendingLock = NSLock()
    private var flushTimer: Timer?
    var lastWineUITime: CFAbsoluteTime = 0

    /// When true, flushPendingEntries() skips pushing to @Published entries,
    /// preventing any SwiftUI re-renders. Messages still enqueue and write to file.
    /// This prevents main thread hang accumulation during Wine execution.
    var uiPaused = false

    struct LogEntry: Identifiable {
        let id = UUID()
        let timestamp: Date
        let message: String
        let level: Level

        enum Level: String {
            case info = "INFO"
            case success = "OK"
            case error = "ERR"
            case debug = "DBG"
        }
    }

    private init() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        logFileURL = docs.appendingPathComponent("mythic-log.txt")

        // Clear log file on each launch
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)

        // Start batch flush timer on main thread
        DispatchQueue.main.async {
            self.flushTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
                self?.flushPendingEntries()
            }
        }

        // Install Wine/wineserver C log callback for UI
        // Rate-limited: only forward ~2 messages/sec to avoid SwiftUI overload
        // (hundreds of mprotect_exec/IAT messages during PE loading would hang the main thread)
        wine_set_ui_log_callback { cStr in
            guard let cStr = cStr else { return }
            let message = String(cString: cStr)
            let isImportant = message.contains("FATAL") || message.contains("FAIL")
                || message.contains("error") || message.contains("SUCCESS")
                || message.contains("ACCEPTED") || message.contains("CONNECTED")
                || message.contains("Wine exited") || message.contains("Wine process")
            let now = CFAbsoluteTimeGetCurrent()
            if !isImportant && (now - LogStore.shared.lastWineUITime) < 0.5 { return }
            LogStore.shared.lastWineUITime = now

            let level: LogStore.LogEntry.Level
            if message.contains("FATAL") || message.contains("FAIL") || message.contains("error") {
                level = .error
            } else if message.contains("SUCCESS") || message.contains("ACCEPTED") || message.contains("CONNECTED") {
                level = .success
            } else {
                level = .debug
            }

            LogStore.shared.enqueue(LogEntry(timestamp: Date(), message: message, level: level))
        }

        // Install C log callback
        jit_set_log_callback { cStr in
            guard let cStr = cStr else { return }
            let message = String(cString: cStr)

            let level: LogEntry.Level
            if message.contains("SUCCESS") || message.contains("passed") {
                level = .success
            } else if message.contains("FAIL") || message.contains("failed") || message.contains("error") {
                level = .error
            } else {
                level = .info
            }

            LogStore.shared.enqueue(LogEntry(timestamp: Date(), message: message, level: level))
            LogStore.shared.appendToFile(message, level: level)
        }
    }

    /// Queue an entry for batched UI update (thread-safe, never blocks main thread)
    private func enqueue(_ entry: LogEntry) {
        pendingLock.lock()
        pendingEntries.append(entry)
        pendingLock.unlock()
    }

    /// Flush pending entries to UI (called by timer on main thread)
    private func flushPendingEntries() {
        // When paused, skip UI updates entirely — zero main thread SwiftUI work
        guard !uiPaused else { return }

        pendingLock.lock()
        guard !pendingEntries.isEmpty else {
            pendingLock.unlock()
            return
        }
        let batch = pendingEntries
        pendingEntries.removeAll()
        pendingLock.unlock()

        entries.append(contentsOf: batch)

        // Cap entries to prevent unbounded growth and SwiftUI overload
        if entries.count > 200 {
            entries.removeFirst(entries.count - 200)
        }
    }

    func log(_ message: String, level: LogEntry.Level = .info) {
        enqueue(LogEntry(timestamp: Date(), message: message, level: level))
        appendToFile(message, level: level)
    }

    private func appendToFile(_ message: String, level: LogEntry.Level = .info) {
        let line = "[\(dateFormatter.string(from: Date()))] [\(level.rawValue)] \(message)\n"
        if let data = line.data(using: .utf8) {
            if let handle = try? FileHandle(forWritingTo: logFileURL) {
                handle.seekToEndOfFile()
                handle.write(data)
                handle.closeFile()
            }
        }
    }

    func clear() {
        pendingLock.lock()
        pendingEntries.removeAll()
        pendingLock.unlock()
        entries.removeAll()
        try? "".write(to: logFileURL, atomically: true, encoding: .utf8)
    }
}
