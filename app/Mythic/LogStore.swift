import Foundation
import SwiftUI

final class LogStore: ObservableObject {
    static let shared = LogStore()

    @Published var entries: [LogEntry] = []

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

            DispatchQueue.main.async {
                LogStore.shared.entries.append(LogEntry(
                    timestamp: Date(),
                    message: message,
                    level: level
                ))
            }
        }
    }

    func log(_ message: String, level: LogEntry.Level = .info) {
        DispatchQueue.main.async {
            self.entries.append(LogEntry(
                timestamp: Date(),
                message: message,
                level: level
            ))
        }
    }

    func clear() {
        entries.removeAll()
    }
}
