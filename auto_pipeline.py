import os
import subprocess
from pathlib import Path

def automate_pipeline(samples_dir):
    base_path = Path(samples_dir)
    results_base = base_path.parent / "results"
    results_base.mkdir(parents=True, exist_ok=True)

    # Lấy tất cả các file trong thư mục samples, bỏ qua các file .zip
    samples = [f for f in base_path.iterdir() if f.is_file() and not f.name.endswith('.zip')]

    if not samples:
        print("[!] Không tìm thấy file mã độc nào đã giải nén. Hãy unzip trước khi chạy.")
        return

    print(f"[*] Tìm thấy {len(samples)} mẫu mã độc cần phân tích.")

    for sample in samples:
        print(f"\n{'='*60}")
        print(f"[*] ĐANG PHÂN TÍCH: {sample.name}")
        print(f"{'='*60}")

        # Tạo thư mục chứa kết quả riêng cho từng file
        sample_out_dir = results_base / sample.name
        sample_out_dir.mkdir(exist_ok=True)

        # Định nghĩa các file đầu ra
        floss_out = sample_out_dir / "floss_out.txt"
        ranked_out = sample_out_dir / "ranked_strings.txt"
        ioc_out = sample_out_dir / "extracted_urls_ips.txt"
        reg_out = sample_out_dir / "extracted_registry.txt"

        # 1. Trích xuất Chuỗi (FLOSS)
        print("  [1/4] FLOSS: Đang giải mã chuỗi thô...")
        subprocess.run(f"floss {sample} > {floss_out}", shell=True, stderr=subprocess.DEVNULL)

        # 2. Xếp hạng (StringSifter)
        print("  [2/4] StringSifter: Đang xếp hạng bằng AI...")
        subprocess.run(f"cat {floss_out} | rank_strings > {ranked_out}", shell=True)

        # 3. Trích xuất IP & URL (iocextract)
        print("  [3/4] iocextract: Đang trích xuất IOCs...")
        subprocess.run(f"iocextract -i {ranked_out} -ip -u > {ioc_out}", shell=True)

        # 4. Trích xuất Registry (grep)
        print("  [4/4] grep: Đang săn khóa Registry...")
        # Sử dụng 4 dấu backslash (\\\\) để Python truyền đúng 2 dấu (\\) xuống shell Linux
        reg_cmd = f"grep -iE '(HKLM|HKCU|HKEY_|Software\\\\\\\\Microsoft\\\\\\\\Windows)' {ranked_out} > {reg_out}"
        subprocess.run(reg_cmd, shell=True)

        print(f"  [v] XONG! Kết quả lưu tại: {sample_out_dir}/")

if __name__ == "__main__":
    # Trỏ thẳng đến thư mục samples của bạn
    target_dir = os.path.join(os.getcwd(), "samples")
    automate_pipeline(target_dir)
