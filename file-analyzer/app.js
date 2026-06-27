/* ═══════════════════════════════════════════════════════════
   RAVEN — File Analysis & Threat Detection Engine
   Client-side binary analysis: type detection, entropy,
   PE parsing, malware indicators, string extraction, hex dump.
   ═══════════════════════════════════════════════════════════ */

// ─── Magic Byte Signatures ───
const MAGIC_SIGNATURES = [
    { bytes: [0x4D, 0x5A],                                     type: 'PE/EXE',       desc: 'Windows Portable Executable',       icon: '⚙', category: 'executable' },
    { bytes: [0x7F, 0x45, 0x4C, 0x46],                         type: 'ELF',          desc: 'Linux ELF Binary',                  icon: '🐧', category: 'executable' },
    { bytes: [0xFE, 0xED, 0xFA, 0xCE],                         type: 'Mach-O',       desc: 'macOS Mach-O Binary (32-bit)',       icon: '🍎', category: 'executable' },
    { bytes: [0xFE, 0xED, 0xFA, 0xCF],                         type: 'Mach-O',       desc: 'macOS Mach-O Binary (64-bit)',       icon: '🍎', category: 'executable' },
    { bytes: [0xCF, 0xFA, 0xED, 0xFE],                         type: 'Mach-O',       desc: 'macOS Mach-O Binary (64-bit LE)',    icon: '🍎', category: 'executable' },
    { bytes: [0xCE, 0xFA, 0xED, 0xFE],                         type: 'Mach-O',       desc: 'macOS Mach-O Binary (32-bit LE)',    icon: '🍎', category: 'executable' },
    { bytes: [0xCA, 0xFE, 0xBA, 0xBE],                         type: 'Java Class',   desc: 'Java Compiled Class File',           icon: '☕', category: 'executable' },
    { bytes: [0x64, 0x65, 0x78, 0x0A],                         type: 'DEX',          desc: 'Android Dalvik Executable',          icon: '🤖', category: 'executable' },
    { bytes: [0x00, 0x61, 0x73, 0x6D],                         type: 'WASM',         desc: 'WebAssembly Binary',                 icon: '🌐', category: 'executable' },
    { bytes: [0x25, 0x50, 0x44, 0x46],                         type: 'PDF',          desc: 'PDF Document',                       icon: '📕', category: 'document' },
    { bytes: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],type: 'OLE/MSI',      desc: 'Microsoft OLE2 / Compound File',     icon: '📄', category: 'document' },
    { bytes: [0x50, 0x4B, 0x03, 0x04],                         type: 'ZIP/Office',   desc: 'ZIP Archive (or DOCX/XLSX/PPTX)',    icon: '📦', category: 'archive' },
    { bytes: [0x50, 0x4B, 0x05, 0x06],                         type: 'ZIP',          desc: 'ZIP Archive (empty)',                icon: '📦', category: 'archive' },
    { bytes: [0x50, 0x4B, 0x07, 0x08],                         type: 'ZIP',          desc: 'ZIP Archive (spanned)',              icon: '📦', category: 'archive' },
    { bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],             type: 'RAR',          desc: 'RAR Archive',                        icon: '📦', category: 'archive' },
    { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],             type: '7z',           desc: '7-Zip Archive',                      icon: '📦', category: 'archive' },
    { bytes: [0x1F, 0x8B],                                     type: 'GZIP',         desc: 'GZIP Compressed',                    icon: '📦', category: 'archive' },
    { bytes: [0x42, 0x5A, 0x68],                               type: 'BZ2',          desc: 'BZIP2 Compressed',                   icon: '📦', category: 'archive' },
    { bytes: [0xFD, 0x37, 0x7A, 0x58, 0x5A],                   type: 'XZ',           desc: 'XZ Compressed',                      icon: '📦', category: 'archive' },
    { bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],type: 'PNG',          desc: 'PNG Image',                          icon: '🖼', category: 'image' },
    { bytes: [0xFF, 0xD8, 0xFF],                               type: 'JPEG',         desc: 'JPEG Image',                         icon: '🖼', category: 'image' },
    { bytes: [0x47, 0x49, 0x46, 0x38],                         type: 'GIF',          desc: 'GIF Image',                          icon: '🖼', category: 'image' },
    { bytes: [0x42, 0x4D],                                     type: 'BMP',          desc: 'Bitmap Image',                       icon: '🖼', category: 'image' },
    { bytes: [0x52, 0x49, 0x46, 0x46],                         type: 'RIFF',         desc: 'RIFF Container (AVI/WAV/WEBP)',      icon: '🎵', category: 'media' },
    { bytes: [0x00, 0x00, 0x00],                               type: 'MP4/MOV',      desc: 'MPEG-4 / QuickTime (ftyp check)',    icon: '🎬', category: 'media', extraCheck: (b) => b.length > 7 && b[3] >= 0x14 && String.fromCharCode(b[4],b[5],b[6],b[7]) === 'ftyp' },
    { bytes: [0x1A, 0x45, 0xDF, 0xA3],                         type: 'MKV/WEBM',     desc: 'Matroska / WebM Video',              icon: '🎬', category: 'media' },
    { bytes: [0x49, 0x44, 0x33],                               type: 'MP3',          desc: 'MP3 Audio (ID3 tag)',                icon: '🎵', category: 'media' },
    { bytes: [0x66, 0x4C, 0x61, 0x43],                         type: 'FLAC',         desc: 'FLAC Audio',                         icon: '🎵', category: 'media' },
    { bytes: [0x4F, 0x67, 0x67, 0x53],                         type: 'OGG',          desc: 'OGG Container',                      icon: '🎵', category: 'media' },
    { bytes: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65],             type: 'SQLite',       desc: 'SQLite Database',                    icon: '🗃', category: 'database' },
    { bytes: [0x7B, 0x5C, 0x72, 0x74, 0x66],                   type: 'RTF',          desc: 'Rich Text Format',                   icon: '📝', category: 'document' },
    { bytes: [0x4C, 0x00, 0x00, 0x00],                         type: 'LNK',          desc: 'Windows Shell Link',                 icon: '🔗', category: 'system', extraCheck: (b) => b.length > 19 && b[4] === 0x01 && b[5] === 0x14 && b[6] === 0x02 && b[7] === 0x00 },
    { bytes: [0x4D, 0x53, 0x43, 0x46],                         type: 'CAB',          desc: 'Microsoft Cabinet Archive',           icon: '📦', category: 'archive' },
    { bytes: [0x25, 0x21, 0x50, 0x53],                         type: 'PostScript',   desc: 'PostScript Document',                icon: '📄', category: 'document' },
    { bytes: [0x49, 0x54, 0x53, 0x46],                         type: 'CHM',          desc: 'Microsoft Compiled HTML Help',        icon: '📖', category: 'document' },
    { bytes: [0x46, 0x57, 0x53],                               type: 'SWF',          desc: 'Adobe Flash (uncompressed)',          icon: '⚡', category: 'media' },
    { bytes: [0x43, 0x57, 0x53],                               type: 'SWF',          desc: 'Adobe Flash (compressed)',            icon: '⚡', category: 'media' },
    { bytes: [0xED, 0xAB, 0xEE, 0xDB],                         type: 'RPM',          desc: 'Linux RPM Package',                  icon: '📦', category: 'archive' },
    { bytes: [0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E],       type: 'DEB/AR',       desc: 'Debian Package / AR Archive',        icon: '📦', category: 'archive' },
    { bytes: [0x78, 0x01],                                     type: 'ZLIB',         desc: 'ZLIB Compressed (low)',               icon: '📦', category: 'archive' },
    { bytes: [0x78, 0x9C],                                     type: 'ZLIB',         desc: 'ZLIB Compressed (default)',           icon: '📦', category: 'archive' },
    { bytes: [0x78, 0xDA],                                     type: 'ZLIB',         desc: 'ZLIB Compressed (best)',              icon: '📦', category: 'archive' },
];

// ─── Suspicious API / String Patterns ───
const MALWARE_PATTERNS = {
    suspiciousAPIs: {
        label: 'Suspicious Windows APIs',
        severity: 'high',
        patterns: [
            'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
            'CreateRemoteThread', 'CreateRemoteThreadEx', 'NtCreateThreadEx',
            'WriteProcessMemory', 'ReadProcessMemory', 'NtWriteVirtualMemory',
            'NtReadVirtualMemory', 'NtAllocateVirtualMemory',
            'OpenProcess', 'NtOpenProcess',
            'QueueUserAPC', 'NtQueueApcThread',
            'SetThreadContext', 'NtSetContextThread',
            'ResumeThread', 'SuspendThread',
            'WinExec', 'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW',
            'URLDownloadToFile', 'URLDownloadToFileA', 'URLDownloadToFileW',
            'WinHttpOpen', 'WinHttpConnect', 'WinHttpSendRequest',
            'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW',
            'HttpSendRequestA', 'HttpSendRequestW',
            'NtUnmapViewOfSection', 'NtMapViewOfSection',
            'RtlCreateUserThread',
            'MiniDumpWriteDump',
            'AmsiScanBuffer', 'AmsiScanString',
            'EtwEventWrite', 'NtTraceEvent',
        ]
    },
    processManipulation: {
        label: 'Process Manipulation',
        severity: 'high',
        patterns: [
            'CreateProcessA', 'CreateProcessW', 'CreateProcessInternalW',
            'NtCreateProcess', 'NtCreateProcessEx', 'RtlCloneUserProcess',
            'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
            'EnumProcesses', 'EnumProcessModules',
            'OpenProcessToken', 'DuplicateTokenEx', 'ImpersonateLoggedOnUser',
            'AdjustTokenPrivileges', 'LookupPrivilegeValue',
            'SetTokenInformation',
        ]
    },
    codeLoading: {
        label: 'Dynamic Code Loading',
        severity: 'medium',
        patterns: [
            'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
            'LdrLoadDll', 'LdrGetProcedureAddress',
            'GetProcAddress', 'GetModuleHandleA', 'GetModuleHandleW',
        ]
    },
    persistence: {
        label: 'Persistence Mechanisms',
        severity: 'high',
        patterns: [
            'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA', 'RegCreateKeyExW',
            'CurrentVersion\\\\Run', 'CurrentVersion\\\\RunOnce',
            'schtasks', 'SchRpcRegisterTask',
            'CreateServiceA', 'CreateServiceW',
            'StartServiceA', 'StartServiceW',
            'ChangeServiceConfig',
        ]
    },
    antiAnalysis: {
        label: 'Anti-Analysis / Evasion',
        severity: 'high',
        patterns: [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess', 'NtSetInformationThread',
            'OutputDebugStringA', 'OutputDebugStringW',
            'GetTickCount', 'QueryPerformanceCounter',
            'FindWindowA', 'FindWindowW',
            'vmware', 'VirtualBox', 'VBOX', 'VMTools', 'Sandboxie',
            'SbieDll', 'dbghelp', 'wireshark', 'fiddler', 'procmon',
            'ollydbg', 'x64dbg', 'x32dbg', 'ida.exe', 'idaq.exe',
        ]
    },
    networkIndicators: {
        label: 'Network Indicators',
        severity: 'medium',
        patterns: [
            'WSAStartup', 'WSASocketA', 'WSASocketW',
            'connect', 'bind', 'listen', 'accept', 'recv', 'send',
            'socket', 'gethostbyname', 'getaddrinfo',
        ]
    },
    cryptoIndicators: {
        label: 'Cryptographic Operations',
        severity: 'low',
        patterns: [
            'CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash',
            'CryptAcquireContext', 'CryptGenKey', 'CryptImportKey',
            'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenerateSymmetricKey',
            'NCryptEncrypt', 'NCryptDecrypt',
        ]
    },
    shellCommands: {
        label: 'Shell / Command Execution',
        severity: 'high',
        patterns: [
            'cmd.exe', 'cmd /c', 'cmd /k',
            'powershell', 'powershell.exe', 'pwsh',
            '-EncodedCommand', '-enc ', '-ep bypass',
            '-ExecutionPolicy Bypass',
            'wscript', 'cscript', 'mshta',
            '/bin/sh', '/bin/bash',
            'wget ', 'curl ',
        ]
    },
    credentialAccess: {
        label: 'Credential Access',
        severity: 'critical',
        patterns: [
            'lsass', 'lsass.exe', 'sekurlsa',
            'mimikatz', 'SafetyKatz', 'SharpKatz',
            'SAM', 'SECURITY', 'SYSTEM',
            'CredEnumerateA', 'CredEnumerateW',
            'CryptUnprotectData', 'DPAPI',
            'vaultcli', 'VaultEnumerateItems',
        ]
    },
    urlPatterns: {
        label: 'Embedded URLs / IPs',
        severity: 'medium',
        isRegex: true,
        patterns: [
            'https?://[\\w\\-\\.]+\\.[a-z]{2,}',
            'ftp://[\\w\\-\\.]+',
            '\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b',
            '\\.onion',
            '\\.i2p',
        ]
    },
    packerSignatures: {
        label: 'Packer / Protector Signatures',
        severity: 'medium',
        patterns: [
            'UPX0', 'UPX1', 'UPX2', 'UPX!',
            '.vmp0', '.vmp1', '.vmp2', 'VMProtect',
            'Themida', '.themida',
            'Enigma', 'EnigmaProtector',
            'ASPack', '.aspack',
            'PECompact',
            '.ndata', 'NullsoftInst',
        ]
    },
};

const EICAR_STRING = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

// ─── PE Machine Types ───
const PE_MACHINES = {
    0x0: 'Unknown', 0x14C: 'i386', 0x166: 'MIPS R4000', 0x184: 'Alpha AXP',
    0x1A2: 'Hitachi SH3', 0x1A6: 'Hitachi SH4', 0x1C0: 'ARM', 0x1C4: 'ARM Thumb-2',
    0x200: 'IA-64', 0x8664: 'AMD64', 0xAA64: 'ARM64',
};

const PE_SUBSYSTEMS = {
    0: 'Unknown', 1: 'Native', 2: 'Windows GUI', 3: 'Windows Console',
    5: 'OS/2 Console', 7: 'POSIX Console', 9: 'Windows CE GUI',
    10: 'EFI Application', 11: 'EFI Boot Service Driver',
    12: 'EFI Runtime Driver', 13: 'EFI ROM', 14: 'Xbox',
    16: 'Windows Boot App',
};

const PE_SECTION_FLAGS = {
    0x00000020: 'CODE',
    0x00000040: 'INITIALIZED_DATA',
    0x00000080: 'UNINITIALIZED_DATA',
    0x02000000: 'DISCARDABLE',
    0x04000000: 'NOT_CACHED',
    0x08000000: 'NOT_PAGED',
    0x10000000: 'SHARED',
    0x20000000: 'EXECUTE',
    0x40000000: 'READ',
    0x80000000: 'WRITE',
};

// ═════════════════════════════════════════════════════════
// Analysis Engine
// ═════════════════════════════════════════════════════════

class FileAnalyzer {
    constructor() {
        this.bytes = null;
        this.allStrings = [];
    }

    async analyze(file) {
        const buffer = await file.arrayBuffer();
        this.bytes = new Uint8Array(buffer);

        const fileInfo = this.getFileInfo(file);
        const fileType = this.detectFileType();
        const entropy = this.calculateEntropy();
        this.allStrings = this.extractStrings(4);
        const malware = this.scanMalware();
        const pe = this.parsePE();
        const threatScore = this.calculateThreatScore(malware, entropy, pe, fileType);

        return { fileInfo, fileType, entropy, strings: this.allStrings, malware, pe, threatScore };
    }

    getFileInfo(file) {
        const b = this.bytes;
        return {
            name: file.name,
            size: file.size,
            sizeFormatted: this.formatSize(file.size),
            type: file.type || 'application/octet-stream',
            lastModified: new Date(file.lastModified).toISOString(),
            md5hint: this.simpleHash(b),
            headerHex: Array.from(b.slice(0, 16)).map(x => x.toString(16).padStart(2, '0').toUpperCase()).join(' '),
        };
    }

    simpleHash(bytes) {
        // FNV-1a 32-bit — fast fingerprint, not cryptographic
        let hash = 0x811C9DC5;
        const len = Math.min(bytes.length, 65536); // cap for speed
        for (let i = 0; i < len; i++) {
            hash ^= bytes[i];
            hash = Math.imul(hash, 0x01000193);
        }
        return (hash >>> 0).toString(16).padStart(8, '0').toUpperCase();
    }

    formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(i ? 2 : 0) + ' ' + units[i];
    }

    detectFileType() {
        const b = this.bytes;
        if (b.length < 2) return { type: 'Unknown', desc: 'File too small to identify', icon: '❓', category: 'unknown', magic: '' };

        for (const sig of MAGIC_SIGNATURES) {
            if (b.length < sig.bytes.length) continue;
            let match = true;
            for (let i = 0; i < sig.bytes.length; i++) {
                if (b[i] !== sig.bytes[i]) { match = false; break; }
            }
            if (match) {
                if (sig.extraCheck && !sig.extraCheck(b)) continue;

                let subType = '';
                // ZIP sub-type detection (Office docs)
                if (sig.type === 'ZIP/Office' && b.length > 30) {
                    const nameBytes = [];
                    const nameLen = b[26] | (b[27] << 8);
                    for (let i = 30; i < 30 + Math.min(nameLen, 100) && i < b.length; i++) {
                        nameBytes.push(String.fromCharCode(b[i]));
                    }
                    const innerName = nameBytes.join('');
                    if (innerName.startsWith('word/')) subType = 'DOCX (Word Document)';
                    else if (innerName.startsWith('xl/')) subType = 'XLSX (Excel Spreadsheet)';
                    else if (innerName.startsWith('ppt/')) subType = 'PPTX (PowerPoint)';
                    else if (innerName.includes('META-INF/')) subType = 'JAR (Java Archive)';
                    else if (innerName.includes('AndroidManifest')) subType = 'APK (Android Package)';
                }

                // RIFF sub-type
                if (sig.type === 'RIFF' && b.length > 12) {
                    const sub = String.fromCharCode(b[8], b[9], b[10], b[11]);
                    if (sub === 'AVI ') subType = 'AVI Video';
                    else if (sub === 'WAVE') subType = 'WAV Audio';
                    else if (sub === 'WEBP') subType = 'WebP Image';
                }

                // LNK false positive: if it's just 4C 00 00 00 but doesn't have the right CLSID, skip
                // (the extraCheck handles this)

                const magicHex = sig.bytes.map(x => x.toString(16).padStart(2, '0').toUpperCase()).join(' ');
                return {
                    type: subType || sig.type,
                    desc: subType ? subType : sig.desc,
                    icon: sig.icon,
                    category: sig.category,
                    magic: magicHex,
                };
            }
        }

        // TAR check at offset 257
        if (b.length > 262) {
            const tarMagic = String.fromCharCode(b[257], b[258], b[259], b[260], b[261]);
            if (tarMagic === 'ustar') {
                return { type: 'TAR', desc: 'TAR Archive', icon: '📦', category: 'archive', magic: '75 73 74 61 72 @257' };
            }
        }

        // Text file heuristic
        let textChars = 0;
        const checkLen = Math.min(b.length, 8192);
        for (let i = 0; i < checkLen; i++) {
            const c = b[i];
            if ((c >= 0x20 && c <= 0x7E) || c === 0x09 || c === 0x0A || c === 0x0D) textChars++;
        }
        if (textChars / checkLen > 0.85) {
            // Try to identify text sub-types
            const head = new TextDecoder('utf-8', { fatal: false }).decode(b.slice(0, Math.min(b.length, 2048)));
            if (head.trim().startsWith('<!DOCTYPE html') || head.trim().startsWith('<html')) return { type: 'HTML', desc: 'HTML Document', icon: '🌐', category: 'text', magic: 'text' };
            if (head.trim().startsWith('<?xml') || head.trim().startsWith('<')) return { type: 'XML', desc: 'XML Document', icon: '📋', category: 'text', magic: 'text' };
            if (head.includes('{') && head.includes('}') && (head.includes('"') || head.includes("'"))) {
                try { JSON.parse(head); return { type: 'JSON', desc: 'JSON Data', icon: '📊', category: 'text', magic: 'text' }; } catch {}
            }
            if (head.startsWith('#!') || head.startsWith('#!/')) {
                const shebang = head.split('\n')[0];
                if (shebang.includes('python')) return { type: 'Python', desc: 'Python Script', icon: '🐍', category: 'script', magic: 'shebang' };
                if (shebang.includes('bash') || shebang.includes('sh')) return { type: 'Shell', desc: 'Shell Script', icon: '🐚', category: 'script', magic: 'shebang' };
                if (shebang.includes('node') || shebang.includes('deno') || shebang.includes('bun')) return { type: 'JavaScript', desc: 'JavaScript', icon: '📜', category: 'script', magic: 'shebang' };
                if (shebang.includes('perl')) return { type: 'Perl', desc: 'Perl Script', icon: '🐪', category: 'script', magic: 'shebang' };
                if (shebang.includes('ruby')) return { type: 'Ruby', desc: 'Ruby Script', icon: '💎', category: 'script', magic: 'shebang' };
                return { type: 'Script', desc: `Script (${shebang.slice(0, 40)})`, icon: '📜', category: 'script', magic: 'shebang' };
            }
            return { type: 'Text', desc: 'Plain Text File', icon: '📝', category: 'text', magic: 'heuristic' };
        }

        return { type: 'Unknown', desc: 'Unknown binary format', icon: '❓', category: 'unknown', magic: '' };
    }

    calculateEntropy() {
        const b = this.bytes;
        if (b.length === 0) return { global: 0, blocks: [], assessment: 'Empty file' };

        // Global entropy
        const globalEntropy = this._shannonEntropy(b, 0, b.length);

        // Per-block entropy (1KB blocks)
        const blockSize = 1024;
        const blocks = [];
        for (let offset = 0; offset < b.length; offset += blockSize) {
            const end = Math.min(offset + blockSize, b.length);
            const ent = this._shannonEntropy(b, offset, end);
            blocks.push({ offset, entropy: ent });
        }

        let assessment;
        if (globalEntropy < 3.0) assessment = 'Low entropy — likely plaintext or mostly null data';
        else if (globalEntropy < 5.0) assessment = 'Normal entropy — typical for structured binary data';
        else if (globalEntropy < 6.5) assessment = 'Moderate entropy — may contain compressed sections';
        else if (globalEntropy < 7.5) assessment = 'High entropy — indicates compression or encryption';
        else assessment = 'Very high entropy — strongly suggests encryption or packing';

        return { global: globalEntropy, blocks, assessment };
    }

    _shannonEntropy(data, start, end) {
        const freq = new Uint32Array(256);
        const len = end - start;
        if (len === 0) return 0;
        for (let i = start; i < end; i++) freq[data[i]]++;
        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (freq[i] === 0) continue;
            const p = freq[i] / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    extractStrings(minLen = 4) {
        const b = this.bytes;
        const results = [];
        const maxStrings = 5000;
        let current = [];
        let startOff = 0;

        for (let i = 0; i < b.length && results.length < maxStrings; i++) {
            const c = b[i];
            if (c >= 0x20 && c <= 0x7E) {
                if (current.length === 0) startOff = i;
                current.push(String.fromCharCode(c));
            } else {
                if (current.length >= minLen) {
                    results.push({ offset: startOff, value: current.join(''), type: 'ascii' });
                }
                current = [];
            }
        }
        if (current.length >= minLen && results.length < maxStrings) {
            results.push({ offset: startOff, value: current.join(''), type: 'ascii' });
        }

        return results;
    }

    scanMalware() {
        const b = this.bytes;
        const indicators = [];

        // EICAR test
        const fileText = new TextDecoder('utf-8', { fatal: false }).decode(b.slice(0, Math.min(b.length, 65536)));
        if (fileText.includes(EICAR_STRING)) {
            indicators.push({
                category: 'EICAR Test Pattern',
                severity: 'critical',
                description: 'EICAR antivirus test string detected — this is a standard AV test file.',
                matches: ['EICAR-STANDARD-ANTIVIRUS-TEST-FILE'],
            });
        }

        // String-based pattern scanning
        const stringValues = this.allStrings.map(s => s.value);
        const fullText = stringValues.join('\n');

        for (const [key, group] of Object.entries(MALWARE_PATTERNS)) {
            const matches = [];

            if (group.isRegex) {
                for (const pattern of group.patterns) {
                    try {
                        const re = new RegExp(pattern, 'gi');
                        const found = fullText.match(re);
                        if (found) {
                            const unique = [...new Set(found)].slice(0, 5);
                            matches.push(...unique);
                        }
                    } catch {}
                }
            } else {
                for (const pattern of group.patterns) {
                    const lowerPattern = pattern.toLowerCase();
                    for (const str of stringValues) {
                        if (str.toLowerCase().includes(lowerPattern)) {
                            if (!matches.includes(pattern)) matches.push(pattern);
                            break;
                        }
                    }
                }
            }

            if (matches.length > 0) {
                indicators.push({
                    category: group.label,
                    severity: group.severity,
                    description: `Found ${matches.length} pattern(s) matching ${group.label.toLowerCase()}.`,
                    matches: matches.slice(0, 10),
                });
            }
        }

        // Entropy-based detection
        const globalEntropy = this._shannonEntropy(b, 0, b.length);
        if (globalEntropy > 7.2 && b.length > 1024) {
            indicators.push({
                category: 'High Entropy Binary',
                severity: 'medium',
                description: `Global entropy is ${globalEntropy.toFixed(3)} — near theoretical maximum. Strongly suggests the binary is packed or encrypted.`,
                matches: [`entropy: ${globalEntropy.toFixed(3)}/8.0`],
            });
        }

        // Double extension detection
        const fileName = ''; // We'll check this separately
        // (handled in the main analyze if we pass the filename)

        return indicators;
    }

    parsePE() {
        const b = this.bytes;
        if (b.length < 64 || b[0] !== 0x4D || b[1] !== 0x5A) return null;

        const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
        const peOffset = view.getUint32(0x3C, true);

        if (peOffset + 24 > b.length) return null;
        if (b[peOffset] !== 0x50 || b[peOffset+1] !== 0x45 || b[peOffset+2] !== 0 || b[peOffset+3] !== 0) return null;

        const coffOffset = peOffset + 4;
        const machine = view.getUint16(coffOffset, true);
        const numSections = view.getUint16(coffOffset + 2, true);
        const timestamp = view.getUint32(coffOffset + 4, true);
        const optHeaderSize = view.getUint16(coffOffset + 16, true);
        const characteristics = view.getUint16(coffOffset + 18, true);

        const optOffset = coffOffset + 20;
        let optMagic = 0, entryPoint = 0, imageBase = 0, subsystem = 0;
        let is64 = false;

        if (optOffset + 2 <= b.length) {
            optMagic = view.getUint16(optOffset, true);
            is64 = optMagic === 0x20B;

            if (optOffset + (is64 ? 112 : 96) <= b.length) {
                entryPoint = view.getUint32(optOffset + 16, true);
                if (is64) {
                    // ImageBase is 8 bytes at offset 24
                    const lo = view.getUint32(optOffset + 24, true);
                    const hi = view.getUint32(optOffset + 28, true);
                    imageBase = hi * 0x100000000 + lo;
                } else {
                    imageBase = view.getUint32(optOffset + 28, true);
                }
                subsystem = view.getUint16(optOffset + (is64 ? 68 : 68), true);
            }
        }

        // Parse sections
        const sectionOffset = optOffset + optHeaderSize;
        const sections = [];
        for (let i = 0; i < numSections && sectionOffset + (i + 1) * 40 <= b.length; i++) {
            const off = sectionOffset + i * 40;
            const nameBytes = b.slice(off, off + 8);
            const name = String.fromCharCode(...nameBytes).replace(/\0/g, '');
            const virtualSize = view.getUint32(off + 8, true);
            const virtualAddr = view.getUint32(off + 12, true);
            const rawSize = view.getUint32(off + 16, true);
            const rawOffset = view.getUint32(off + 20, true);
            const chars = view.getUint32(off + 36, true);

            // Section entropy
            let sectionEntropy = 0;
            if (rawOffset + rawSize <= b.length && rawSize > 0) {
                sectionEntropy = this._shannonEntropy(b, rawOffset, rawOffset + rawSize);
            }

            const flags = [];
            for (const [bit, label] of Object.entries(PE_SECTION_FLAGS)) {
                if (chars & parseInt(bit)) flags.push(label);
            }

            sections.push({
                name, virtualSize, virtualAddr, rawSize, rawOffset,
                characteristics: chars, flags, entropy: sectionEntropy,
            });
        }

        // Parse imports (basic)
        const imports = [];
        if (optOffset + (is64 ? 112 : 96) + 8 <= b.length) {
            const numDataDirs = view.getUint32(optOffset + (is64 ? 108 : 92), true);
            if (numDataDirs > 1) {
                const importRVA = view.getUint32(optOffset + (is64 ? 120 : 104), true);
                const importSize = view.getUint32(optOffset + (is64 ? 124 : 108), true);

                if (importRVA > 0 && importSize > 0) {
                    // Convert RVA to file offset
                    const importFileOffset = this._rvaToOffset(importRVA, sections);
                    if (importFileOffset !== null) {
                        for (let i = 0; i < 200; i++) { // max 200 DLLs
                            const entryOff = importFileOffset + i * 20;
                            if (entryOff + 20 > b.length) break;

                            const nameRVA = view.getUint32(entryOff + 12, true);
                            if (nameRVA === 0) break;

                            const nameOff = this._rvaToOffset(nameRVA, sections);
                            if (nameOff === null || nameOff >= b.length) break;

                            let dllName = '';
                            for (let j = nameOff; j < b.length && b[j] !== 0 && j - nameOff < 256; j++) {
                                dllName += String.fromCharCode(b[j]);
                            }
                            if (dllName) imports.push(dllName);
                        }
                    }
                }
            }
        }

        // Characteristics flags
        const charFlags = [];
        if (characteristics & 0x0002) charFlags.push('EXECUTABLE');
        if (characteristics & 0x0020) charFlags.push('LARGE_ADDRESS_AWARE');
        if (characteristics & 0x0100) charFlags.push('32BIT');
        if (characteristics & 0x2000) charFlags.push('DLL');
        if (characteristics & 0x0001) charFlags.push('RELOCS_STRIPPED');
        if (characteristics & 0x0004) charFlags.push('LINE_NUMS_STRIPPED');
        if (characteristics & 0x0200) charFlags.push('DEBUG_STRIPPED');

        return {
            machine: PE_MACHINES[machine] || `0x${machine.toString(16)}`,
            is64,
            numSections,
            timestamp: new Date(timestamp * 1000).toISOString(),
            timestampRaw: timestamp,
            entryPoint: `0x${entryPoint.toString(16).toUpperCase()}`,
            imageBase: `0x${imageBase.toString(16).toUpperCase()}`,
            subsystem: PE_SUBSYSTEMS[subsystem] || `Unknown (${subsystem})`,
            characteristics: charFlags,
            sections,
            imports,
            isDLL: !!(characteristics & 0x2000),
        };
    }

    _rvaToOffset(rva, sections) {
        for (const sec of sections) {
            if (rva >= sec.virtualAddr && rva < sec.virtualAddr + sec.virtualSize) {
                return rva - sec.virtualAddr + sec.rawOffset;
            }
        }
        return null;
    }

    calculateThreatScore(malware, entropy, pe, fileType) {
        let score = 0;
        const breakdown = [];

        // Indicator scoring
        const severityWeight = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };
        for (const ind of malware) {
            const weight = severityWeight[ind.severity] || 5;
            const add = Math.min(weight * Math.min(ind.matches.length, 3), 30);
            score += add;
            breakdown.push({
                label: ind.category,
                severity: ind.severity,
                points: add,
            });
        }

        // Entropy penalty
        if (entropy.global > 7.5) {
            score += 15;
            breakdown.push({ label: 'Very high entropy', severity: 'high', points: 15 });
        } else if (entropy.global > 7.0) {
            score += 8;
            breakdown.push({ label: 'High entropy', severity: 'medium', points: 8 });
        }

        // PE-specific checks
        if (pe) {
            // Executable + writable sections
            for (const sec of pe.sections) {
                if ((sec.characteristics & 0x20000000) && (sec.characteristics & 0x80000000)) {
                    score += 10;
                    breakdown.push({ label: `Section "${sec.name}" is EXECUTE+WRITE`, severity: 'high', points: 10 });
                    break; // only penalize once
                }
            }

            // High entropy sections in PE
            for (const sec of pe.sections) {
                if (sec.entropy > 7.0 && sec.rawSize > 512) {
                    score += 8;
                    breakdown.push({ label: `Section "${sec.name}" entropy ${sec.entropy.toFixed(2)}`, severity: 'medium', points: 8 });
                    break;
                }
            }

            // Very few imports (possible dynamic resolution)
            if (pe.imports.length <= 2 && pe.imports.length > 0) {
                score += 10;
                breakdown.push({ label: 'Very few imports (dynamic resolution?)', severity: 'medium', points: 10 });
            }

            // Suspicious section names
            const suspSections = ['.vmp0', '.vmp1', '.vmp2', 'UPX0', 'UPX1', 'UPX2', '.themida', '.enigma'];
            for (const sec of pe.sections) {
                if (suspSections.some(s => sec.name.toLowerCase().startsWith(s.toLowerCase()))) {
                    score += 12;
                    breakdown.push({ label: `Packer section: "${sec.name}"`, severity: 'high', points: 12 });
                    break;
                }
            }
        }

        score = Math.min(score, 100);

        let verdict, level;
        if (score <= 15) { verdict = 'CLEAN'; level = 'clean'; }
        else if (score <= 40) { verdict = 'LOW RISK'; level = 'clean'; }
        else if (score <= 65) { verdict = 'SUSPICIOUS'; level = 'suspicious'; }
        else { verdict = 'LIKELY MALICIOUS'; level = 'malicious'; }

        return { score, verdict, level, breakdown };
    }

    generateHexDump(offset, length) {
        const b = this.bytes;
        const start = Math.min(offset, b.length);
        const end = Math.min(start + length, b.length);
        const lines = [];

        for (let i = start; i < end; i += 16) {
            const addr = i.toString(16).padStart(8, '0').toUpperCase();
            const hexParts = [];
            const asciiParts = [];

            for (let j = 0; j < 16; j++) {
                if (i + j < end) {
                    const byte = b[i + j];
                    let cls = 'hex-byte';
                    if (byte === 0) cls = 'hex-byte-null';
                    else if (byte >= 0x20 && byte <= 0x7E) cls = 'hex-byte-ascii';
                    else if (byte > 0x7E) cls = 'hex-byte-high';

                    hexParts.push(`<span class="${cls}">${byte.toString(16).padStart(2, '0')}</span>`);

                    if (byte >= 0x20 && byte <= 0x7E) {
                        const ch = String.fromCharCode(byte).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
                        asciiParts.push(`<span class="hex-ascii-printable">${ch}</span>`);
                    } else {
                        asciiParts.push('<span class="hex-ascii">.</span>');
                    }
                } else {
                    hexParts.push('  ');
                    asciiParts.push(' ');
                }

                if (j === 7) hexParts.push('<span class="hex-separator"> </span>');
            }

            lines.push(
                `<span class="hex-offset">${addr}</span>  ${hexParts.join(' ')}  │${asciiParts.join('')}│`
            );
        }

        return lines.join('\n');
    }
}

// ═════════════════════════════════════════════════════════
// UI Controller
// ═════════════════════════════════════════════════════════

const analyzer = new FileAnalyzer();
let currentResults = null;
let hexCurrentPage = 0;
const HEX_PAGE_SIZE = 512; // bytes per page (32 rows * 16)

// ─── DOM Elements ───
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const browseLink = document.getElementById('browseLink');
const loadingSection = document.getElementById('loadingSection');
const loadingFill = document.getElementById('loadingFill');
const results = document.getElementById('results');
const newAnalysisBtn = document.getElementById('newAnalysisBtn');

// ─── Event Listeners ───
dropZone.addEventListener('click', () => fileInput.click());
browseLink.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
fileInput.addEventListener('change', (e) => { if (e.target.files[0]) handleFile(e.target.files[0]); });

dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
});

newAnalysisBtn.addEventListener('click', () => {
    results.classList.add('hidden');
    dropZone.classList.remove('hidden');
    fileInput.value = '';
});

// Card collapse
document.querySelectorAll('.card-header[data-target]').forEach(header => {
    header.addEventListener('click', () => {
        const card = document.getElementById(header.dataset.target);
        card.classList.toggle('collapsed');
    });
});

// String filter
const stringFilter = document.getElementById('stringFilter');
const stringMinLen = document.getElementById('stringMinLen');
stringFilter.addEventListener('input', renderStrings);
stringMinLen.addEventListener('change', renderStrings);

// Hex controls
document.getElementById('hexPrevBtn').addEventListener('click', () => navigateHex(-1));
document.getElementById('hexNextBtn').addEventListener('click', () => navigateHex(1));
document.getElementById('hexJump').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        const val = parseInt(e.target.value, 16);
        if (!isNaN(val)) {
            hexCurrentPage = Math.floor(val / HEX_PAGE_SIZE);
            renderHex();
        }
    }
});

// ─── Main Handler ───
async function handleFile(file) {
    dropZone.classList.add('hidden');
    results.classList.add('hidden');
    loadingSection.classList.remove('hidden');

    // Animated loading bar
    loadingFill.style.width = '0%';
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress > 90) progress = 90;
        loadingFill.style.width = progress + '%';
    }, 150);

    try {
        currentResults = await analyzer.analyze(file);
        clearInterval(progressInterval);
        loadingFill.style.width = '100%';

        await new Promise(r => setTimeout(r, 300));

        loadingSection.classList.add('hidden');
        results.classList.remove('hidden');

        renderResults(currentResults);
    } catch (err) {
        clearInterval(progressInterval);
        loadingSection.classList.add('hidden');
        dropZone.classList.remove('hidden');
        console.error('Analysis failed:', err);
        alert('Analysis failed: ' + err.message);
    }
}

// ─── Renderers ───
function renderResults(r) {
    renderThreatGauge(r.threatScore);
    renderFileInfo(r.fileInfo);
    renderFileType(r.fileType);
    renderEntropy(r.entropy);
    renderMalware(r.malware, r.threatScore);
    renderPE(r.pe);
    renderStrings();
    hexCurrentPage = 0;
    renderHex();
}

function renderThreatGauge(threat) {
    const card = document.getElementById('threatOverviewCard');
    card.className = 'result-card threat-overview threat-' + threat.level;

    // Draw gauge on canvas
    const canvas = document.getElementById('threatGauge');
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    const cx = w / 2, cy = h - 10;
    const radius = 90;
    const startAngle = Math.PI;
    const endAngle = 2 * Math.PI;

    // Track
    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, endAngle);
    ctx.strokeStyle = 'rgba(255,255,255,0.06)';
    ctx.lineWidth = 14;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Fill
    const fillAngle = startAngle + (threat.score / 100) * Math.PI;
    const gradient = ctx.createLinearGradient(cx - radius, cy, cx + radius, cy);
    gradient.addColorStop(0, '#00ff88');
    gradient.addColorStop(0.5, '#ffaa00');
    gradient.addColorStop(1, '#ff3356');

    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, fillAngle);
    ctx.strokeStyle = gradient;
    ctx.lineWidth = 14;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Tick marks
    for (let i = 0; i <= 10; i++) {
        const angle = startAngle + (i / 10) * Math.PI;
        const innerR = radius + 10;
        const outerR = radius + (i % 5 === 0 ? 18 : 14);
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(angle) * innerR, cy + Math.sin(angle) * innerR);
        ctx.lineTo(cx + Math.cos(angle) * outerR, cy + Math.sin(angle) * outerR);
        ctx.strokeStyle = 'rgba(255,255,255,0.15)';
        ctx.lineWidth = 1;
        ctx.stroke();
    }

    // Score number
    const scoreEl = document.getElementById('threatScoreNum');
    scoreEl.textContent = threat.score;
    scoreEl.style.color = threat.level === 'clean' ? '#00ff88' : threat.level === 'suspicious' ? '#ffaa00' : '#ff3356';

    // Badge
    const badge = document.getElementById('threatBadge');
    badge.className = 'threat-verdict-badge verdict-' + threat.level;
    document.getElementById('verdictText').textContent = threat.verdict;

    // Summary
    const summaryEl = document.getElementById('threatSummary');
    if (threat.score === 0) {
        summaryEl.textContent = 'No suspicious indicators detected. File appears clean.';
    } else if (threat.level === 'clean') {
        summaryEl.textContent = `Minor indicators found (score: ${threat.score}/100). Likely benign — common APIs detected.`;
    } else if (threat.level === 'suspicious') {
        summaryEl.textContent = `Multiple suspicious indicators (score: ${threat.score}/100). Manual review recommended.`;
    } else {
        summaryEl.textContent = `High-confidence malicious indicators (score: ${threat.score}/100). Treat as hostile.`;
    }

    // Breakdown tags
    const breakdownEl = document.getElementById('threatBreakdown');
    breakdownEl.innerHTML = threat.breakdown.map(b => {
        const cls = b.severity === 'critical' || b.severity === 'high' ? 'tag-high' :
                    b.severity === 'medium' ? 'tag-medium' :
                    b.severity === 'low' ? 'tag-low' : 'tag-info';
        return `<span class="breakdown-tag ${cls}">+${b.points} ${b.label}</span>`;
    }).join('');
}

function renderFileInfo(info) {
    const grid = document.getElementById('fileInfoGrid');
    const items = [
        { label: 'File Name', value: info.name },
        { label: 'File Size', value: `${info.sizeFormatted} (${info.size.toLocaleString()} bytes)` },
        { label: 'MIME Type', value: info.type },
        { label: 'Last Modified', value: info.lastModified },
        { label: 'FNV-1a Hash', value: info.md5hint },
        { label: 'Header (16B)', value: info.headerHex },
    ];
    grid.innerHTML = items.map(i => `
        <div class="info-item">
            <div class="info-label">${i.label}</div>
            <div class="info-value">${escapeHtml(i.value)}</div>
        </div>
    `).join('');
}

function renderFileType(ft) {
    const el = document.getElementById('fileTypeContent');
    el.innerHTML = `
        <div class="file-type-display">
            <div class="type-badge">
                <span class="type-badge-icon">${ft.icon}</span>
                <div class="type-badge-text">
                    <span class="type-name">${escapeHtml(ft.type)}</span>
                    <span class="type-desc">${escapeHtml(ft.desc)}</span>
                </div>
            </div>
            <div class="type-details">
                <div class="type-detail-row">
                    <span class="type-detail-label">Category</span>
                    <span class="type-detail-value">${ft.category}</span>
                </div>
                <div class="type-detail-row">
                    <span class="type-detail-label">Magic Bytes</span>
                    <span class="type-detail-value">${ft.magic || 'N/A'}</span>
                </div>
                <div class="type-detail-row">
                    <span class="type-detail-label">Detection</span>
                    <span class="type-detail-value">${ft.magic === 'heuristic' || ft.magic === 'text' ? 'Heuristic' : ft.magic === 'shebang' ? 'Shebang' : 'Signature'}</span>
                </div>
            </div>
        </div>
    `;
}

function renderEntropy(ent) {
    const statsEl = document.getElementById('entropyStats');
    const globalClass = ent.global < 3 ? 'entropy-low' : ent.global < 5.5 ? 'entropy-medium' : ent.global < 7 ? 'entropy-high' : 'entropy-very-high';

    // Find min/max block entropy
    let minBlock = 8, maxBlock = 0;
    for (const block of ent.blocks) {
        if (block.entropy < minBlock) minBlock = block.entropy;
        if (block.entropy > maxBlock) maxBlock = block.entropy;
    }

    statsEl.innerHTML = `
        <div class="entropy-summary">
            <div class="entropy-stat">
                <span class="entropy-stat-label">Global Entropy</span>
                <span class="entropy-stat-value ${globalClass}">${ent.global.toFixed(4)}</span>
            </div>
            <div class="entropy-stat">
                <span class="entropy-stat-label">Max Block</span>
                <span class="entropy-stat-value ${maxBlock > 7 ? 'entropy-very-high' : 'entropy-medium'}">${maxBlock.toFixed(4)}</span>
            </div>
            <div class="entropy-stat">
                <span class="entropy-stat-label">Min Block</span>
                <span class="entropy-stat-value ${minBlock < 2 ? 'entropy-low' : 'entropy-medium'}">${minBlock.toFixed(4)}</span>
            </div>
            <div class="entropy-stat">
                <span class="entropy-stat-label">Blocks</span>
                <span class="entropy-stat-value entropy-medium">${ent.blocks.length}</span>
            </div>
        </div>
        <p class="entropy-note">${ent.assessment}</p>
    `;

    // Draw entropy chart
    const canvas = document.getElementById('entropyCanvas');
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.clientWidth * dpr;
    canvas.height = 180 * dpr;
    ctx.scale(dpr, dpr);
    const w = canvas.clientWidth, h = 180;

    ctx.clearRect(0, 0, w, h);

    if (ent.blocks.length === 0) return;

    const padding = { top: 10, bottom: 25, left: 40, right: 10 };
    const chartW = w - padding.left - padding.right;
    const chartH = h - padding.top - padding.bottom;

    // Grid lines
    ctx.strokeStyle = 'rgba(255,255,255,0.05)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 8; i++) {
        const y = padding.top + chartH - (i / 8) * chartH;
        ctx.beginPath();
        ctx.moveTo(padding.left, y);
        ctx.lineTo(w - padding.right, y);
        ctx.stroke();

        if (i % 2 === 0) {
            ctx.fillStyle = 'rgba(255,255,255,0.25)';
            ctx.font = '10px JetBrains Mono';
            ctx.textAlign = 'right';
            ctx.fillText(i.toString(), padding.left - 5, y + 3);
        }
    }

    // Entropy bars
    const barWidth = Math.max(1, chartW / ent.blocks.length);
    for (let i = 0; i < ent.blocks.length; i++) {
        const e = ent.blocks[i].entropy;
        const barH = (e / 8) * chartH;
        const x = padding.left + (i / ent.blocks.length) * chartW;
        const y = padding.top + chartH - barH;

        // Color based on entropy
        let color;
        if (e < 3) color = 'rgba(0,255,136,0.6)';
        else if (e < 5.5) color = 'rgba(0,212,255,0.6)';
        else if (e < 7) color = 'rgba(255,170,0,0.6)';
        else color = 'rgba(255,51,86,0.7)';

        ctx.fillStyle = color;
        ctx.fillRect(x, y, Math.max(barWidth - 0.5, 1), barH);
    }

    // Danger zone line at 7.0
    const dangerY = padding.top + chartH - (7.0 / 8) * chartH;
    ctx.strokeStyle = 'rgba(255,51,86,0.4)';
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(padding.left, dangerY);
    ctx.lineTo(w - padding.right, dangerY);
    ctx.stroke();
    ctx.setLineDash([]);

    ctx.fillStyle = 'rgba(255,51,86,0.5)';
    ctx.font = '9px JetBrains Mono';
    ctx.textAlign = 'left';
    ctx.fillText('packed/encrypted threshold', padding.left + 5, dangerY - 4);

    // X-axis label
    ctx.fillStyle = 'rgba(255,255,255,0.3)';
    ctx.font = '10px JetBrains Mono';
    ctx.textAlign = 'center';
    ctx.fillText('File Offset →', w / 2, h - 5);
}

function renderMalware(indicators, threatScore) {
    const el = document.getElementById('malwareContent');

    if (indicators.length === 0) {
        el.innerHTML = `
            <div class="no-threats">
                <div class="no-threats-icon">✓</div>
                <p>No suspicious indicators detected.</p>
            </div>
        `;
        return;
    }

    // Group by severity
    const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const grouped = {};
    for (const ind of indicators) {
        if (!grouped[ind.severity]) grouped[ind.severity] = [];
        grouped[ind.severity].push(ind);
    }

    let html = '';
    for (const sev of sevOrder) {
        if (!grouped[sev]) continue;
        html += `<div class="indicator-group">`;
        html += `<div class="indicator-group-header"><span class="indicator-severity severity-${sev}">${sev.toUpperCase()}</span> ${grouped[sev].length} indicator(s)</div>`;
        html += `<div class="indicator-items">`;
        for (const ind of grouped[sev]) {
            html += `
                <div class="indicator-item ind-${sev}">
                    <span class="indicator-desc">
                        <strong>${escapeHtml(ind.category)}</strong><br>
                        ${escapeHtml(ind.description)}
                    </span>
                    <span class="indicator-matches">${ind.matches.map(m => escapeHtml(m)).join(', ')}</span>
                </div>
            `;
        }
        html += `</div></div>`;
    }

    el.innerHTML = html;
}

function renderPE(pe) {
    const card = document.getElementById('peCard');
    if (!pe) { card.classList.add('hidden'); return; }
    card.classList.remove('hidden');

    const el = document.getElementById('peContent');
    let html = '';

    // General info
    html += `<div class="pe-section"><div class="pe-section-title">COFF / Optional Header</div>`;
    html += `<div class="info-grid">`;
    html += infoItem('Machine', pe.machine);
    html += infoItem('Architecture', pe.is64 ? 'PE32+ (64-bit)' : 'PE32 (32-bit)');
    html += infoItem('Entry Point', pe.entryPoint);
    html += infoItem('Image Base', pe.imageBase);
    html += infoItem('Subsystem', pe.subsystem);
    html += infoItem('Timestamp', pe.timestamp);
    html += infoItem('Type', pe.isDLL ? 'DLL' : 'EXE');
    html += infoItem('Sections', pe.numSections.toString());
    html += `</div>`;
    // Characteristics
    html += `<div style="margin-top:0.5rem">${pe.characteristics.map(c => `<span class="pe-flag">${c}</span>`).join(' ')}</div>`;
    html += `</div>`;

    // Sections
    html += `<div class="pe-section"><div class="pe-section-title">Sections (${pe.sections.length})</div>`;
    html += `<div style="overflow-x:auto"><table class="pe-table">`;
    html += `<tr><th>Name</th><th>V.Size</th><th>V.Addr</th><th>Raw Size</th><th>Raw Offset</th><th>Entropy</th><th>Flags</th></tr>`;
    for (const sec of pe.sections) {
        const entClass = sec.entropy > 7 ? 'entropy-very-high' : sec.entropy > 6 ? 'entropy-high' : '';
        const isRWX = (sec.characteristics & 0x20000000) && (sec.characteristics & 0x80000000);
        html += `<tr>`;
        html += `<td>${escapeHtml(sec.name)}</td>`;
        html += `<td>0x${sec.virtualSize.toString(16).toUpperCase()}</td>`;
        html += `<td>0x${sec.virtualAddr.toString(16).toUpperCase()}</td>`;
        html += `<td>0x${sec.rawSize.toString(16).toUpperCase()}</td>`;
        html += `<td>0x${sec.rawOffset.toString(16).toUpperCase()}</td>`;
        html += `<td class="${entClass}">${sec.entropy.toFixed(3)}</td>`;
        html += `<td>${sec.flags.map(f => {
            const cls = (f === 'EXECUTE' || f === 'WRITE') && isRWX ? 'pe-flag flag-warn' : 'pe-flag';
            return `<span class="${cls}">${f}</span>`;
        }).join(' ')}</td>`;
        html += `</tr>`;
    }
    html += `</table></div></div>`;

    // Imports
    if (pe.imports.length > 0) {
        html += `<div class="pe-section"><div class="pe-section-title">Imported DLLs (${pe.imports.length})</div>`;
        html += `<div style="display:flex;flex-wrap:wrap;gap:0.3rem">`;
        for (const dll of pe.imports) {
            const isSusp = ['ws2_32.dll','winhttp.dll','wininet.dll','urlmon.dll','advapi32.dll','ntdll.dll'].some(
                d => dll.toLowerCase() === d
            );
            html += `<span class="pe-flag${isSusp ? ' flag-warn' : ''}">${escapeHtml(dll)}</span>`;
        }
        html += `</div></div>`;
    }

    el.innerHTML = html;
}

function renderStrings() {
    const el = document.getElementById('stringsContent');
    const countEl = document.getElementById('stringCount');
    if (!currentResults) return;

    const minLen = parseInt(stringMinLen.value) || 8;
    const filter = stringFilter.value.toLowerCase();

    let filtered = currentResults.strings.filter(s => s.value.length >= minLen);
    if (filter) filtered = filtered.filter(s => s.value.toLowerCase().includes(filter));

    countEl.textContent = `${filtered.length} strings`;

    // Limit display
    const display = filtered.slice(0, 500);

    // Check if string is suspicious
    const suspKeywords = [];
    for (const group of Object.values(MALWARE_PATTERNS)) {
        if (!group.isRegex) suspKeywords.push(...group.patterns.map(p => p.toLowerCase()));
    }

    el.innerHTML = display.map(s => {
        const isSusp = suspKeywords.some(k => s.value.toLowerCase().includes(k));
        return `<div class="string-row">
            <span class="string-offset">0x${s.offset.toString(16).padStart(8, '0')}</span>
            <span class="string-value${isSusp ? ' str-suspicious' : ''}">${escapeHtml(s.value)}</span>
        </div>`;
    }).join('');

    if (filtered.length > 500) {
        el.innerHTML += `<div class="string-row" style="color:var(--text-dim);justify-content:center">... ${filtered.length - 500} more strings not shown ...</div>`;
    }
}

function renderHex() {
    if (!analyzer.bytes) return;
    const total = analyzer.bytes.length;
    const totalPages = Math.ceil(total / HEX_PAGE_SIZE);
    hexCurrentPage = Math.max(0, Math.min(hexCurrentPage, totalPages - 1));

    const offset = hexCurrentPage * HEX_PAGE_SIZE;
    const html = analyzer.generateHexDump(offset, HEX_PAGE_SIZE);
    document.getElementById('hexDumpPre').innerHTML = html;
    document.getElementById('hexPageInfo').textContent = `Page ${hexCurrentPage + 1} / ${totalPages}  (0x${offset.toString(16).toUpperCase()})`;

    document.getElementById('hexPrevBtn').disabled = hexCurrentPage === 0;
    document.getElementById('hexNextBtn').disabled = hexCurrentPage >= totalPages - 1;
}

function navigateHex(dir) {
    hexCurrentPage += dir;
    renderHex();
}

// ─── Helpers ───
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function infoItem(label, value) {
    return `<div class="info-item"><div class="info-label">${label}</div><div class="info-value">${escapeHtml(value)}</div></div>`;
}
