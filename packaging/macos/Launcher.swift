import AppKit

final class WardrApplication: NSObject, NSApplicationDelegate {
    private let dashboard = Process()

    func applicationDidFinishLaunching(_ notification: Notification) {
        let menu = NSMenu()
        let root = NSMenuItem()
        menu.addItem(root)
        root.submenu = NSMenu()
        root.submenu?.addItem(withTitle: "Quit Wardr", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        NSApp.mainMenu = menu

        guard let payload = Bundle.main.resourceURL?.appendingPathComponent("payload") else {
            showFailure("The Wardr installer payload is missing.")
            return
        }
        let location = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Wardr Runtime", isDirectory: true)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try prepare(payload: payload, location: location)
                DispatchQueue.main.async { self.launch(location: location) }
            } catch {
                DispatchQueue.main.async { self.showFailure(error.localizedDescription) }
            }
        }
    }

    private func launch(location: URL) {
        dashboard.executableURL = location.appendingPathComponent("venv/bin/python3")
        dashboard.arguments = ["-I", "-m", "wardr"]
        dashboard.standardInput = FileHandle.nullDevice
        dashboard.standardOutput = FileHandle.nullDevice
        dashboard.standardError = FileHandle.nullDevice
        dashboard.terminationHandler = { child in
            DispatchQueue.main.async {
                if child.terminationStatus == 0 {
                    NSApp.terminate(nil)
                } else {
                    self.showFailure("Wardr could not start its local dashboard.")
                }
            }
        }
        do {
            try dashboard.run()
        } catch {
            showFailure(error.localizedDescription)
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        if dashboard.isRunning {
            dashboard.terminate()
        }
    }

    private func showFailure(_ message: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Wardr could not start"
        alert.informativeText = message
        alert.runModal()
        NSApp.terminate(nil)
    }
}

func prepare(payload: URL, location: URL) throws {
    let setup = Process()
    let output = Pipe()
    setup.executableURL = payload.appendingPathComponent("python/bin/python3")
    setup.arguments = ["-I", payload.appendingPathComponent("install.py").path, "--install-dir", location.path]
    setup.standardInput = FileHandle.nullDevice
    setup.standardOutput = output
    setup.standardError = output
    try setup.run()
    let diagnostic = output.fileHandleForReading.readDataToEndOfFile()
    setup.waitUntilExit()
    if setup.terminationStatus != 0 {
        let message = String(data: diagnostic, encoding: .utf8) ?? "Wardr setup failed."
        throw NSError(domain: "Wardr Setup", code: Int(setup.terminationStatus),
                      userInfo: [NSLocalizedDescriptionKey: message])
    }
}

let prepareOnly = CommandLine.arguments.dropFirst().first == "--prepare-only"
if prepareOnly, CommandLine.arguments.count == 3, let payload = Bundle.main.resourceURL?.appendingPathComponent("payload") {
    do {
        try prepare(payload: payload, location: URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true))
    } catch {
        FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
        exit(1)
    }
} else {
    let application = NSApplication.shared
    let delegate = WardrApplication()
    application.delegate = delegate
    application.setActivationPolicy(.regular)
    application.run()
}
