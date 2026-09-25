import Foundation
import PhishCore
import Synchronization
import XCTest
@testable import PhishGuard

/// The gate that keeps MLX off the GPU unless PhishGuard is frontmost, and the pieces `MLXClassifier` builds on
/// top of it (a generation handle cancellable from the thread that flips the state).
final class ForegroundGateTests: XCTestCase {
    func testGateStartsClosedAndFollowsTheLifecycle() {
        XCTAssertFalse(AppForegroundGate().isForeground, "a process launched into the background must not assume it may use the GPU")
        let gate = AppForegroundGate(isForeground: true)
        XCTAssertTrue(gate.isForeground)
        gate.setForeground(false)
        XCTAssertFalse(gate.isForeground)
        gate.setForeground(true)
        XCTAssertTrue(gate.isForeground)
    }

    func testObserversAreCalledSynchronouslyAndOnlyOnChange() {
        let gate = AppForegroundGate(isForeground: true)
        let states = Mutex<[Bool]>([])
        let subscription = gate.onForegroundChange { isForeground in
            states.withLock { $0.append(isForeground) }
        }

        gate.setForeground(false)
        // Synchronously: by the time `setForeground` returns, an in-flight generation has already been cancelled.
        XCTAssertEqual(states.withLock { $0 }, [false])
        gate.setForeground(false)
        XCTAssertEqual(states.withLock { $0 }, [false], "no callback without a change")
        gate.setForeground(true)
        XCTAssertEqual(states.withLock { $0 }, [false, true])

        subscription.cancel()
        gate.setForeground(false)
        XCTAssertEqual(states.withLock { $0 }, [false, true], "a cancelled subscription stops receiving changes")
    }

    /// How `MLXClassifier` stops generating: the gate's observer cancels the published generation task without
    /// hopping onto the classifier actor (which is suspended awaiting that very task).
    func testClosingTheGateCancelsThePublishedGeneration() async throws {
        let gate = AppForegroundGate(isForeground: true)
        let handle = GenerationHandle()
        let subscription = gate.onForegroundChange { isForeground in
            if !isForeground { handle.cancel() }
        }
        defer { subscription.cancel() }

        let started = expectation(description: "generation started")
        let generation = Task { () async throws -> String in
            started.fulfill()
            // Stands in for mlx-swift-lm's token loop, which checks `Task.isCancelled` between tokens.
            while !Task.isCancelled {
                try await Task.sleep(for: .milliseconds(5))
            }
            throw CancellationError()
        }
        handle.adopt(generation)
        await fulfillment(of: [started], timeout: 2)

        gate.setForeground(false)
        XCTAssertTrue(generation.isCancelled, "cancellation is set before setForeground returns")
        do {
            _ = try await generation.value
            XCTFail("expected the generation to be cancelled")
        } catch is CancellationError {
            // expected
        }
        handle.clear()
    }

    func testAdoptingASecondGenerationCancelsThePrevious() async {
        let handle = GenerationHandle()
        let first = Task { () async throws -> String in
            while !Task.isCancelled { await Task.yield() }
            return "first"
        }
        handle.adopt(first)
        let second = Task { () async throws -> String in "second" }
        handle.adopt(second)
        XCTAssertTrue(first.isCancelled)
        _ = try? await first.value
        _ = try? await second.value
        handle.clear()
        handle.cancel() // no generation published: a no-op, not a crash
    }
}
