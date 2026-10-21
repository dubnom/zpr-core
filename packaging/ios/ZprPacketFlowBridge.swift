import Darwin
import Dispatch
import Foundation
import NetworkExtension
import PhFFI

final class ZprPacketFlowBridge {
    typealias StartCompletion = (Error?) -> Void
    typealias FailureHandler = (Error) -> Void

    private enum State {
        case stopped
        case starting
        case ready
        case stopping
    }

    private static let startupTimeout: DispatchTimeInterval = .seconds(30)
    private static let maxQueuedPackets = 256
    private static let maxQueuedBytes = 4 * 1024 * 1024
    private static let maxPacketSize = 65_535

    private let packetFlow: NEPacketTunnelFlow
    private let configPath: String
    private let failureHandler: FailureHandler
    private let queue = DispatchQueue(label: "org.zpr.ph.packet-flow")

    private var state = State.stopped
    private var engineHandle: OpaquePointer?
    private var hostFD: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var writeRetry: DispatchSourceTimer?
    private var queuedInbound: [Data] = []
    private var queuedInboundBytes = 0
    private var startCompletion: StartCompletion?
    private var packetReadPending = false

    init(
        packetFlow: NEPacketTunnelFlow,
        configPath: String,
        failureHandler: @escaping FailureHandler
    ) {
        self.packetFlow = packetFlow
        self.configPath = configPath
        self.failureHandler = failureHandler
    }

    func start(completion: @escaping StartCompletion) {
        queue.async {
            guard case .stopped = self.state else {
                completion(self.error("packet-flow bridge has already been started"))
                return
            }
            guard self.configPath.hasPrefix("/") else {
                completion(self.error("adapter config path must be absolute"))
                return
            }

            self.state = .starting
            self.startCompletion = completion
            do {
                try self.createSocketPairAndStartEngine()
                self.startRustPacketReader()
                self.pollEngineReadiness(until: .now() + Self.startupTimeout)
            } catch {
                self.fail(error)
            }
        }
    }

    func stop(completion: @escaping (Error?) -> Void) {
        queue.async {
            guard case .stopped = self.state else {
                self.stopEngine(completion: completion)
                return
            }
            completion(nil)
        }
    }

    private func createSocketPairAndStartEngine() throws {
        var descriptors: [Int32] = [-1, -1]
        let result = descriptors.withUnsafeMutableBufferPointer {
            socketpair(AF_UNIX, SOCK_DGRAM, 0, $0.baseAddress!)
        }
        guard result == 0 else {
            throw posixError("socketpair")
        }

        do {
            try setNonblocking(descriptors[0])
            try setNonblocking(descriptors[1])
            hostFD = descriptors[1]

            let handle = configPath.withCString {
                ph_ios_start($0, descriptors[0])
            }
            close(descriptors[0])
            descriptors[0] = -1
            guard let handle else {
                throw error(lastErrorMessage())
            }
            engineHandle = handle
        } catch {
            if descriptors[0] >= 0 {
                close(descriptors[0])
            }
            if hostFD >= 0 {
                close(hostFD)
                hostFD = -1
            } else if descriptors[1] >= 0 {
                close(descriptors[1])
            }
            throw error
        }
    }

    private func setNonblocking(_ fd: Int32) throws {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            throw posixError("fcntl")
        }
    }

    private func startRustPacketReader() {
        let source = DispatchSource.makeReadSource(fileDescriptor: hostFD, queue: queue)
        source.setEventHandler { [weak self] in
            self?.drainRustPackets()
        }
        source.resume()
        readSource = source
    }

    private func pollEngineReadiness(until deadline: DispatchTime) {
        guard case .starting = state, let engineHandle else { return }

        switch ph_ios_status(engineHandle) {
        case UInt32(PH_IOS_READY.rawValue):
            state = .ready
            let completion = startCompletion
            startCompletion = nil
            completion?(nil)
            requestPacketsFromHost()
            monitorEngineStatus()
        case UInt32(PH_IOS_STOPPED.rawValue):
            fail(error("packet handler stopped before becoming ready"))
        default:
            guard DispatchTime.now() < deadline else {
                fail(error("timed out waiting for the ZPR peer connection"))
                return
            }
            queue.asyncAfter(deadline: .now() + .milliseconds(100)) { [weak self] in
                self?.pollEngineReadiness(until: deadline)
            }
        }
    }

    private func requestPacketsFromHost() {
        guard case .ready = state, !packetReadPending, queuedInbound.isEmpty else { return }
        packetReadPending = true
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.queue.async {
                self.packetReadPending = false
                self.enqueueHostPackets(packets)
            }
        }
    }

    private func monitorEngineStatus() {
        guard case .ready = state, let engineHandle else { return }
        if ph_ios_status(engineHandle) == UInt32(PH_IOS_STOPPED.rawValue) {
            fail(error("packet handler stopped unexpectedly"))
            return
        }
        queue.asyncAfter(deadline: .now() + .milliseconds(250)) { [weak self] in
            self?.monitorEngineStatus()
        }
    }

    private func enqueueHostPackets(_ packets: [Data]) {
        guard case .ready = state else { return }
        for packet in packets {
            guard !packet.isEmpty, packet.count <= Self.maxPacketSize else {
                fail(error("Network Extension supplied an invalid IP packet size"))
                return
            }
            guard queuedInbound.count < Self.maxQueuedPackets,
                  queuedInboundBytes + packet.count <= Self.maxQueuedBytes
            else {
                fail(error("packet-flow input queue is full; stopping the tunnel rather than dropping silently"))
                return
            }
            queuedInbound.append(packet)
            queuedInboundBytes += packet.count
        }
        flushHostPacketsToRust()
    }

    private func flushHostPacketsToRust() {
        while let packet = queuedInbound.first {
            let sent = packet.withUnsafeBytes {
                Darwin.send(hostFD, $0.baseAddress, $0.count, 0)
            }
            if sent == packet.count {
                queuedInbound.removeFirst()
                queuedInboundBytes -= packet.count
                continue
            }
            if sent == -1, errno == EAGAIN || errno == EWOULDBLOCK {
                scheduleWriteRetry()
                return
            }
            fail(posixError("send packet to Rust"))
            return
        }

        writeRetry?.cancel()
        writeRetry = nil
        requestPacketsFromHost()
    }

    private func scheduleWriteRetry() {
        guard writeRetry == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(10), repeating: .milliseconds(10))
        timer.setEventHandler { [weak self] in
            self?.flushHostPacketsToRust()
        }
        timer.resume()
        writeRetry = timer
    }

    private func drainRustPackets() {
        guard case .ready = state else { return }
        var buffer = [UInt8](repeating: 0, count: Self.maxPacketSize)
        var packets: [Data] = []
        var protocols: [NSNumber] = []

        while true {
            let received = buffer.withUnsafeMutableBytes {
                Darwin.recv(hostFD, $0.baseAddress, $0.count, 0)
            }
            if received > 0 {
                let packet = Data(buffer.prefix(received))
                guard let protocolNumber = protocolNumber(for: packet) else {
                    fail(error("Rust produced a malformed IP packet"))
                    return
                }
                packets.append(packet)
                protocols.append(NSNumber(value: protocolNumber))
                continue
            }
            if received == -1, errno == EAGAIN || errno == EWOULDBLOCK {
                break
            }
            fail(posixError("receive packet from Rust"))
            return
        }

        if !packets.isEmpty, !packetFlow.writePackets(packets, withProtocols: protocols) {
            fail(error("Network Extension rejected packets from the ZPR engine"))
        }
    }

    private func protocolNumber(for packet: Data) -> Int32? {
        guard let firstByte = packet.first else { return nil }
        switch firstByte >> 4 {
        case 4 where packet.count >= 20:
            return AF_INET
        case 6 where packet.count >= 40:
            return AF_INET6
        default:
            return nil
        }
    }

    private func fail(_ failure: Error) {
        guard case .stopping = state else {
            let completion = startCompletion
            startCompletion = nil
            if let completion {
                completion(failure)
            } else {
                failureHandler(failure)
            }
            stopEngine { _ in }
            return
        }
    }

    private func stopEngine(completion: @escaping (Error?) -> Void) {
        guard case .stopping = state else {
            state = .stopping
            startCompletion?(error("packet-flow bridge stopped during startup"))
            startCompletion = nil
            let sources = [readSource, writeRetry].compactMap { $0 }
            readSource = nil
            writeRetry = nil

            let cancellationGroup = DispatchGroup()
            for source in sources {
                cancellationGroup.enter()
                source.setEventHandler {}
                source.setCancelHandler {
                    cancellationGroup.leave()
                }
                source.cancel()
            }
            cancellationGroup.notify(queue: queue) {
                var stopError: Error?
                if let engineHandle = self.engineHandle {
                    let result = ph_ios_stop(engineHandle)
                    if result != 0 {
                        stopError = self.error("Rust packet handler stopped with status \(result)")
                    }
                    self.engineHandle = nil
                }
                if self.hostFD >= 0 {
                    close(self.hostFD)
                    self.hostFD = -1
                }
                self.queuedInbound.removeAll(keepingCapacity: false)
                self.queuedInboundBytes = 0
                self.state = .stopped
                completion(stopError)
            }
            return
        }
        completion(error("packet-flow bridge is already stopping"))
    }

    private func lastErrorMessage() -> String {
        guard let pointer = ph_ios_last_error() else {
            return "Rust packet handler failed without an error message"
        }
        return String(cString: pointer)
    }

    private func posixError(_ operation: String) -> NSError {
        NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "\(operation): \(String(cString: strerror(errno)))"]
        )
    }

    private func error(_ message: String) -> NSError {
        NSError(
            domain: "org.zpr.ph.packet-flow",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}
