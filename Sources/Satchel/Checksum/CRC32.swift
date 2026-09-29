/// CRC-32 (IEEE 802.3, 다항식 0xEDB88320) — zip 규격의 체크섬. slice-by-8.
public struct CRC32: Sendable {
    /// 8 × 256 테이블. `tables[0..<256]` 이 표준 바이트 테이블이다.
    static let tables: [UInt32] = {
        var t = [UInt32](repeating: 0, count: 8 * 256)
        for n in 0..<256 {
            var c = UInt32(n)
            for _ in 0..<8 { c = (c & 1) != 0 ? (0xEDB8_8320 ^ (c >> 1)) : (c >> 1) }
            t[n] = c
        }
        for k in 1..<8 {
            for n in 0..<256 {
                let prev = t[(k - 1) * 256 + n]
                t[k * 256 + n] = (prev >> 8) ^ t[Int(prev & 0xFF)]
            }
        }
        return t
    }()

    private var state: UInt32 = 0xFFFF_FFFF

    public init() {}

    public mutating func update(_ bytes: [UInt8]) {
        var c = state
        CRC32.tables.withUnsafeBufferPointer { t in
            bytes.withUnsafeBufferPointer { b in
                var i = 0
                let n = b.count
                while i + 8 <= n {
                    var lo = UInt32(b[i])
                    lo |= UInt32(b[i + 1]) << 8
                    lo |= UInt32(b[i + 2]) << 16
                    lo |= UInt32(b[i + 3]) << 24
                    lo ^= c
                    var hi = UInt32(b[i + 4])
                    hi |= UInt32(b[i + 5]) << 8
                    hi |= UInt32(b[i + 6]) << 16
                    hi |= UInt32(b[i + 7]) << 24
                    var x: UInt32 = t[7 * 256 + Int(lo & 0xFF)]
                    x ^= t[6 * 256 + Int((lo >> 8) & 0xFF)]
                    x ^= t[5 * 256 + Int((lo >> 16) & 0xFF)]
                    x ^= t[4 * 256 + Int(lo >> 24)]
                    x ^= t[3 * 256 + Int(hi & 0xFF)]
                    x ^= t[2 * 256 + Int((hi >> 8) & 0xFF)]
                    x ^= t[1 * 256 + Int((hi >> 16) & 0xFF)]
                    x ^= t[Int(hi >> 24)]
                    c = x
                    i += 8
                }
                while i < n {
                    c = t[Int((c ^ UInt32(b[i])) & 0xFF)] ^ (c >> 8)
                    i += 1
                }
            }
        }
        state = c
    }

    public var value: UInt32 { state ^ 0xFFFF_FFFF }

    public static func checksum(_ bytes: [UInt8]) -> UInt32 {
        var crc = CRC32()
        crc.update(bytes)
        return crc.value
    }

    /// 전처리·후처리(반전) 없는 한 바이트 갱신 — ZipCrypto 키 갱신에 쓴다.
    @inline(__always)
    static func step(_ crc: UInt32, _ byte: UInt8) -> UInt32 {
        tables[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
    }
}
