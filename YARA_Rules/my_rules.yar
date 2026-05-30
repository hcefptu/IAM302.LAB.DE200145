// 1. Quét Magic Bytes: Nhận diện mọi file thực thi của Windows (PE/EXE)
rule Detect_Windows_EXE {
    meta:
        author = "Student"
        description = "Bắt các file có Header MZ kinh điển"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}

// 2. Quét từ khóa tống tiền: Nhận diện họ Ransomware
rule Detect_Ransomware_Strings {
    meta:
        description = "Bắt các chuỗi thường thấy khi bị tống tiền"
    strings:
        $s1 = "bitcoin" nocase
        $s2 = "decrypt" nocase
        $s3 = "wallet" nocase
        $s4 = "pay" nocase
    condition:
        2 of ($s*) // Chỉ cần khớp 2 trong 4 từ là báo động
}

// 3. Quét hành vi đóng gói: Phát hiện mã độc dùng UPX Packer
rule Detect_UPX_Packed {
    meta:
        description = "Tìm dấu vết UPX packer nhằm qua mặt Antivirus"
    strings:
        $u1 = "UPX0"
        $u2 = "UPX1"
    condition:
        uint16(0) == 0x5a4d and all of them // Phải là file EXE và có cả 2 chuỗi UPX
}

// 4. Quét Macro nguy hiểm: Bắt mã độc ẩn trong Word/Excel (VBA)
rule Detect_Suspicious_Macro {
    meta:
        description = "Phát hiện hàm tự động chạy trong tài liệu Office"
    strings:
        $m1 = "AutoOpen" nocase
        $m2 = "Document_Open" nocase
        $m3 = "Shell" fullword nocase
    condition:
        ($m1 or $m2) and $m3 // File tự động mở VÀ có gọi lệnh Shell hệ thống
}

// 5. Quét Hex (Mã máy): Bắt Shellcode NOP Sled
rule Detect_NOP_Sled {
    meta:
        description = "Phát hiện chuỗi byte 0x90 dài (đặc trưng của Exploit)"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop_sled
}

// 6. Quét bằng Biểu thức chính quy (Regex): Bắt IP cứng của C2 Server
rule Detect_Hardcoded_IP {
    meta:
        description = "Dùng Regex để tìm các địa chỉ IP bị ghim chết trong code"
    strings:
        $ip_regex = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    condition:
        $ip_regex
}

// 7. Thuật toán kích thước: Nhận diện Dropper/Downloader siêu nhỏ
rule Detect_Tiny_Dropper {
    meta:
        description = "File EXE nhưng dung lượng cực kỳ nhỏ (nhỏ hơn 30KB)"
    condition:
        uint16(0) == 0x5a4d and filesize < 30KB
}

// 8. Quét đa nền tảng: Nhận diện mã độc trên Linux (ELF binary)
rule Detect_Linux_ELF {
    meta:
        description = "Bắt Magic byte của file thực thi Linux"
    strings:
        $elf_magic = { 7F 45 4C 46 } // Tương đương \x7fELF
    condition:
        $elf_magic at 0
}

// 9. Quét File văn bản: Bắt PDF nhúng JavaScript độc hại
rule Detect_Malicious_PDF {
    meta:
        description = "Phát hiện PDF có chứa script ẩn"
    strings:
        $pdf = "%PDF-"
        $js1 = "/JavaScript"
        $js2 = "/JS"
    condition:
        $pdf at 0 and (1 of ($js*))
}

// 10. Luật kết hợp siêu chặt (Advanced Heuristic)
rule Advanced_Malware_Logic {
    meta:
        description = "EXE + Kích thước nhỏ + Gọi CMD ẩn"
    strings:
        $sus_cmd = "cmd.exe /c" nocase
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and $sus_cmd
}
