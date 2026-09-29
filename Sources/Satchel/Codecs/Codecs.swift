import Compression
import Foundation

/// 저장 (압축 없음, 방식 0).
public struct StoreCodec: CompressionCodec {
    static let id: UInt16 = 0
    public init() {}
    public var methodID: UInt16 { Self.id }
    public var versionNeededToExtract: UInt16 { 10 }
    public func makeCompressor() throws -> any ByteTransform { PassThroughTransform() }
    public func makeDecompressor() throws -> any ByteTransform { PassThroughTransform() }
}

/// DEFLATE (방식 8) — `Compression` 프레임워크의 `COMPRESSION_ZLIB`(헤더 없는 raw DEFLATE).
public struct DeflateCodec: CompressionCodec {
    static let id: UInt16 = 8
    public init() {}
    public var methodID: UInt16 { Self.id }
    public var versionNeededToExtract: UInt16 { 20 }
    public func makeCompressor() throws -> any ByteTransform { try CompressionStreamTransform(encoding: true) }
    public func makeDecompressor() throws -> any ByteTransform { try CompressionStreamTransform(encoding: false) }
}

final class PassThroughTransform: ByteTransform {
    func process(_ input: [UInt8]) throws -> [UInt8] { input }
    func finish() throws -> [UInt8] { [] }
}

final class CompressionStreamTransform: ByteTransform {
    private let stream: UnsafeMutablePointer<compression_stream>
    private let buffer: UnsafeMutablePointer<UInt8>
    private let bufferSize = ZipLimits.chunkSize
    private let encoding: Bool
    private var ended = false

    init(encoding: Bool) throws {
        self.encoding = encoding
        stream = .allocate(capacity: 1)
        buffer = .allocate(capacity: bufferSize)
        let status = compression_stream_init(
            stream, encoding ? COMPRESSION_STREAM_ENCODE : COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB)
        guard status == COMPRESSION_STATUS_OK else {
            stream.deallocate()
            buffer.deallocate()
            throw ZipError.unsupported("compression stream init failed")
        }
    }

    deinit {
        compression_stream_destroy(stream)
        stream.deallocate()
        buffer.deallocate()
    }

    func process(_ input: [UInt8]) throws -> [UInt8] { try run(input, finalize: false) }
    func finish() throws -> [UInt8] { try run([], finalize: true) }

    private func run(_ input: [UInt8], finalize: Bool) throws -> [UInt8] {
        // 해제: 스트림이 끝난 뒤 들어오는 바이트는 무시한다 (크기는 호출하는 쪽이 검증).
        if ended { return [] }
        var output: [UInt8] = []
        let flags = finalize ? Int32(bitPattern: COMPRESSION_STREAM_FINALIZE.rawValue) : 0
        try input.withUnsafeBufferPointer { src in
            stream.pointee.src_ptr = src.baseAddress ?? UnsafePointer(buffer)
            stream.pointee.src_size = src.count
            while true {
                stream.pointee.dst_ptr = buffer
                stream.pointee.dst_size = bufferSize
                let status = compression_stream_process(stream, flags)
                let produced = bufferSize - stream.pointee.dst_size
                if produced > 0 { output.append(contentsOf: UnsafeBufferPointer(start: buffer, count: produced)) }
                switch status {
                case COMPRESSION_STATUS_END:
                    ended = true
                    return
                case COMPRESSION_STATUS_OK:
                    let inputDone = stream.pointee.src_size == 0
                    let outputRoom = stream.pointee.dst_size > 0
                    if !finalize {
                        if inputDone && outputRoom { return }
                    } else if !encoding && inputDone && outputRoom && produced == 0 {
                        throw ZipError.corrupted(entry: nil, reason: "truncated deflate stream")
                    }
                default:
                    throw ZipError.corrupted(entry: nil, reason: "invalid deflate data")
                }
            }
        }
        return output
    }
}
