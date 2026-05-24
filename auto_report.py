import os
import subprocess
from pathlib import Path

def run_extract(cmd):
    """Chạy lệnh, hứng text, lọc dòng trống và loại bỏ trùng lặp"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        lines = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        return list(set(lines))
    except Exception:
        return []

def print_section(title, items):
    """In toàn bộ danh sách kết quả (Không giới hạn)"""
    print(f"\n[+] {title}")
    if not items:
        print("  -> Không tìm thấy dữ liệu.")
    else:
        for item in items:
            print(f"  - {item}")

def summarize_malware(sample_path):
    sample_name = sample_path.name
    print(f"\n{'='*70}")
    print(f"[*] ĐANG TỔNG HỢP BÁO CÁO TOÀN DIỆN: {sample_name}")
    print(f"{'='*70}")

    temp_ranked = f"/tmp/{sample_name}_ranked.txt"
    
    # ---------------------------------------------------------
    # GIAI ĐOẠN 1: QUY TRÌNH CƠ BẢN (Tạo mỏ dữ liệu)
    # ---------------------------------------------------------
    print("  [>] Đang chạy FLOSS & StringSifter (Quá trình này tốn vài phút)...")
    subprocess.run(f"floss '{sample_path}' | rank_strings > '{temp_ranked}'", shell=True, stderr=subprocess.DEVNULL)

    # ---------------------------------------------------------
    # GIAI ĐOẠN 2: PHÂN TÍCH SÂU (Threat Hunting)
    # Dựa trên 4 kỹ thuật nâng cao từ hướng dẫn Lab
    # ---------------------------------------------------------
    print("  [>] Đang săn lùng chuỗi ẩn bằng FLOSS nâng cao (Stack/Decoded)...")
    # Tắt thông báo rườm rà của FLOSS (-q) để lấy chuỗi tinh khiết
    stack_strings = run_extract(f"floss -q --only decoded stack -- '{sample_path}'")

    print("  [>] Đang trích xuất Mạng & Email & Hashes (iocextract)...")
    ips = run_extract(f"iocextract -ip '{temp_ranked}'")
    urls = run_extract(f"iocextract -u '{temp_ranked}'")
    emails = run_extract(f"iocextract -e '{temp_ranked}'")
    hashes = run_extract(f"iocextract --hashes '{temp_ranked}'")

    print("  [>] Đang quét Chỉ báo Hành vi & Lệnh ngầm (grep Regex)...")
    # Sử dụng raw string (r"") để Python truyền an toàn ký tự Regex và \ xuống Linux shell
    regs = run_extract(r"grep -iE '(HKLM|HKCU|HKEY_|Software\\Microsoft\\Windows)' '" + temp_ranked + "'")
    dropped = run_extract(r"grep -iE '\.(exe|dll|bat|vbs|ps1|sys)$' '" + temp_ranked + "'")
    lotl = run_extract(r"grep -iE '(cmd\.exe|powershell|/c |WScript)' '" + temp_ranked + "'")
    pdbs = run_extract(r"grep -i '\.pdb$' '" + temp_ranked + "'")
    apis = run_extract(r"grep -iE '(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|SetWindowsHookEx|URLDownloadToFile)' '" + temp_ranked + "'")

    # ---------------------------------------------------------
    # GIAI ĐOẠN 3: IN BÁO CÁO HOÀN CHỈNH
    # ---------------------------------------------------------
    print(f"\n" + "-"*20 + f" BÁO CÁO THREAT INTEL: {sample_name} " + "-"*20)
    
    print("\n--- I. MẠNG & DANH TÍNH KẺ TẤN CÔNG ---")
    print_section("Địa chỉ IP (Nghi ngờ C&C):", ips)
    print_section("URLs / Domains (Tải Payload):", urls)
    print_section("Địa chỉ Email (Exfiltration):", emails)
    print_section("Mã băm nhúng sẵn (Blacklist/Integrity):", hashes)

    print("\n--- II. DẤU VẾT HỆ THỐNG (Persistence & Dropper) ---")
    print_section("Khóa Registry (Cài cắm khởi động):", regs)
    print_section("Tệp tin nghi ngờ thả xuống (Dropped Files):", dropped)

    print("\n--- III. CHỈ BÁO HÀNH VI (Behavioral IOCs) ---")
    print_section("Đường dẫn PDB (Thông tin biên dịch):", pdbs)
    print_section("Lệnh ngầm hệ thống (Living off the Land):", lotl)
    print_section("Hàm API Nhạy cảm (Injection/Keylogger):", apis)
    print_section("Chuỗi ẩn (Stack/Decoded Strings):", stack_strings)

    # Dọn dẹp file tạm
    if os.path.exists(temp_ranked):
        os.remove(temp_ranked)

def main():
    samples_dir = Path("samples")
    if not samples_dir.exists() or not any(samples_dir.iterdir()):
        print("[!] Thư mục 'samples' không tồn tại hoặc chưa có file mã độc giải nén.")
        return

    malwares = [f for f in samples_dir.iterdir() if f.is_file() and not f.name.endswith('.zip')]
    
    print(f"\n{'>'*15} HỆ THỐNG THREAT HUNTING TỰ ĐỘNG {'<'*15}")
    print(f"[*] Tìm thấy {len(malwares)} mẫu mã độc. Bắt đầu chuỗi phân tích...\n")

    for sample in malwares:
        summarize_malware(sample)
        
    print(f"\n{'='*70}")
    print("[v] HOÀN TẤT TOÀN BỘ QUÁ TRÌNH TỰ ĐỘNG HÓA BÁO CÁO!")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()
