import Darwin

/// 系统相关 API
enum SystemUtils {
    
    /// 调整文件描述符限制
    static func adjustNofile() {
        var lim = rlimit()
        
        // 获取当前文件描述符限制
        guard getrlimit(RLIMIT_NOFILE, &lim) == 0 else {
            debugPrint("getrlimit NOFILE failed, \(String(cString: strerror(errno)))")
            return
        }
        
        // 如果当前限制不等于最大限制，进行调整
        if lim.rlim_cur != lim.rlim_max {
            tracePrint("rlimit NOFILE \(lim) requires adjustment")
            var newLim = lim
            newLim.rlim_cur = newLim.rlim_max
            
            // 处理 macOS 特殊情况
            #if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
            var maxFilesPerProc: Int32 = 0
            var size = MemoryLayout<Int32>.size
            var mib = [CTL_KERN, KERN_MAXFILESPERPROC]
            
            // 通过 sysctl 获取最大文件数
            if sysctl(&mib, 2, &maxFilesPerProc, &size, nil, 0) == 0 {
                newLim.rlim_cur = rlim_t(maxFilesPerProc)
            } else {
                debugPrint("sysctlbyname kern.maxfilesperproc failed, \(String(cString: strerror(errno)))")
            }
            #endif
            
            // 设置新限制
            guard setrlimit(RLIMIT_NOFILE, &newLim) == 0 else {
                debugPrint("setrlimit NOFILE \(newLim) failed, \(String(cString: strerror(errno)))")
                return
            }
            debugPrint("rlimit NOFILE adjusted to \(newLim)")
        }
    }
    
    /// 切换运行用户身份
    static func runAsUser(_ username: String) throws {
        guard let passwd = getPasswd(username) else {
            throw NSError(domain: "System", code: 1, userInfo: [NSLocalizedDescriptionKey: "User \(username) not found"])
        }
        
        // 先设置组 ID
        guard setgid(passwd.pw_gid) == 0 else {
            let error = String(cString: strerror(errno))
            throw NSError(domain: "System", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "Failed to setgid for \(username): \(error)"
            ])
        }
        
        // 设置补充组
        guard initgroups(passwd.pw_name, passwd.pw_gid) == 0 else {
            let error = String(cString: strerror(errno))
            throw NSError(domain: "System", code: 3, userInfo: [
                NSLocalizedDescriptionKey: "Failed to initgroups for \(username): \(error)"
            ])
        }
        
        // 设置用户 ID
        guard setuid(passwd.pw_uid) == 0 else {
            let error = String(cString: strerror(errno))
            throw NSError(domain: "System", code: 4, userInfo: [
                NSLocalizedDescriptionKey: "Failed to setuid for \(username): \(error)"
            ])
        }
    }
    
    // MARK: - 私有方法
    private static func getPasswd(_ username: String) -> passwd? {
        // 尝试解析为 UID
        if let uid = uid_t(username) {
            return getpwuid(uid)?.pointee
        }
        
        // 按用户名查询
        return withUnsafeTemporaryAllocation(of: Int8.self, capacity: 1024) { buffer in
            var result: UnsafeMutablePointer<passwd>? = nil
            var pwd = passwd()
            getpwnam_r(username, &pwd, buffer.baseAddress!, buffer.count, &result)
            return result?.pointee
        }
    }
    
    // 调试输出（可替换为实际日志库）
    private static func debugPrint(_ message: String) {
        #if DEBUG
        print("[DEBUG] \(message)")
        #endif
    }
    
    // 跟踪输出（可替换为实际日志库）
    private static func tracePrint(_ message: String) {
        #if DEBUG
        print("[TRACE] \(message)")
        #endif
    }
}

// 扩展 rlimit 的 CustomStringConvertible 实现
extension rlimit: CustomStringConvertible {
    public var description: String {
        return "(cur: \(rlim_cur), max: \(rlim_max))"
    }
}

// 扩展 passwd 的字符串转换
extension passwd {
    var pw_name: String {
        return String(cString: self.pw_name)
    }
}
