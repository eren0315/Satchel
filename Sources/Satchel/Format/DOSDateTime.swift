import Foundation

/// MS-DOS 날짜·시간 (로컬 시간대, 2초 단위, 1980–2107).
enum DOSDateTime {
    private static func calendar() -> Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .current
        return calendar
    }

    static func encode(_ date: Date) -> (time: UInt16, date: UInt16) {
        let c = calendar().dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        guard let year = c.year, let month = c.month, let day = c.day,
              let hour = c.hour, let minute = c.minute, let second = c.second, year >= 1980 else {
            return (0, (1 << 5) | 1)   // 1980-01-01 00:00:00
        }
        if year > 2107 { return (UInt16(23 << 11 | 59 << 5 | 29), UInt16(127 << 9 | 12 << 5 | 31)) }
        let d = UInt16((year - 1980) << 9 | month << 5 | day)
        let t = UInt16(hour << 11 | minute << 5 | second / 2)
        return (t, d)
    }

    static func decode(time: UInt16, date: UInt16) -> Date? {
        var c = DateComponents()
        c.year = Int(date >> 9) + 1980
        c.month = Int((date >> 5) & 0x0F)
        c.day = Int(date & 0x1F)
        c.hour = Int(time >> 11)
        c.minute = Int((time >> 5) & 0x3F)
        c.second = Int(time & 0x1F) * 2
        guard let month = c.month, (1...12).contains(month),
              let day = c.day, (1...31).contains(day),
              let hour = c.hour, hour < 24, let minute = c.minute, minute < 60 else { return nil }
        return calendar().date(from: c)
    }
}
