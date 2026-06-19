import os
import re
import ctypes
from ctypes import wintypes

# Định nghĩa cấu trúc WIN32_FIND_STREAM_DATA chuẩn Win32
class WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [
        ("StreamSize", ctypes.c_longlong),
        ("cStreamName", wintypes.WCHAR * 296)
    ]

# Khởi tạo đối tượng kernel32
kernel32 = ctypes.windll.kernel32

# --- KHAI BÁO KIỂU DỮ LIỆU TƯỜNG MINH ĐỂ TRỊ LỖI 64-BIT ---
kernel32.FindFirstStreamW.argtypes = [
    wintypes.LPCWSTR,       # lpFileName
    ctypes.c_int,           # InfoLevel (Luôn là 0)
    ctypes.c_void_p,        # lpFindStreamData
    wintypes.DWORD          # dwFlags (Luôn là 0)
]
kernel32.FindFirstStreamW.restype = wintypes.HANDLE  # Trả về Handle 64-bit chuẩn

kernel32.FindNextStreamW.argtypes = [
    wintypes.HANDLE,        # hFindStream
    ctypes.c_void_p         # lpFindStreamData
]
kernel32.FindNextStreamW.restype = wintypes.BOOL

kernel32.FindClose.argtypes = [wintypes.HANDLE]
kernel32.FindClose.restype = wintypes.BOOL

# Giá trị Handle không hợp lệ trên Windows 64-bit
INVALID_HANDLE_VALUE = -1
INVALID_HANDLE_VALUE_64 = 18446744073709551615

DANGEROUS_EXTENSIONS = ['.exe', '.ps1', '.bat', '.vbs', '.cmd', '.dll', '.scr', '.sys']

def enumerate_streams(file_path):
    """Sử dụng Windows API đã được định nghĩa kiểu chuẩn để liệt kê các stream"""
    streams = []
    find_data = WIN32_FIND_STREAM_DATA()
    
    # Thêm tiền tố chống lỗi đường dẫn dài nếu cần
    if not file_path.startswith("\\\\?\\"):
        if file_path.startswith("\\\\"):
            file_path = "\\\\?\\UNC\\" + file_path[2:]
        else:
            file_path = "\\\\?\\" + file_path

    handle = kernel32.FindFirstStreamW(file_path, 0, ctypes.byref(find_data), 0)
    
    if handle and handle != INVALID_HANDLE_VALUE and handle != INVALID_HANDLE_VALUE_64:
        try:
            streams.append(find_data.cStreamName)
            # Vòng lặp an toàn không còn bị crash bộ nhớ
            while kernel32.FindNextStreamW(handle, ctypes.byref(find_data)):
                streams.append(find_data.cStreamName)
        finally:
            kernel32.FindClose(handle)
    return streams

def check_invalid_zone_id(file_path):
    """Đọc luồng Zone.Identifier để kiểm tra tính hợp lệ của ZoneId"""
    zone_path = f"{file_path}:Zone.Identifier"
    if os.path.exists(zone_path):
        try:
            with open(zone_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            match = re.search(r'ZoneId\s*=\s*(-?\d+)', content)
            if match:
                zone_id = int(match.group(1))
                if zone_id < 0 or zone_id > 4:
                    return f"ZoneId rủi ro/không hợp lệ (ZoneId = {zone_id})"
            else:
                return "Luồng Zone.Identifier bị cấu trúc lạ (Không thấy ZoneId)"
        except:
            return "Không thể đọc nội dung luồng Zone.Identifier"
    return None

def scan_directory(target_dir):
    print(f"[*] Bat dau quet nhanh thu muc: {target_dir}")
    print("=" * 60)
    
    count_files = 0
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            count_files += 1
            full_path = os.path.join(root, file)
            streams = enumerate_streams(full_path)
            
            # 1. Kiểm tra số lượng stream bất thường
            if len(streams) > 2:
                print(f"[!] CANH BAO SO LUONG: File co so luong luong du lieu bat thuong ({len(streams)} luong)!")
                print(f" L- File: {full_path}")
                print(f" L- Cac luong phat hien: {', '.join(streams)}\n")
            
            # 2. Kiểm tra tên nguy hiểm & ZoneId
            for stream in streams:
                stream_lower = stream.lower()
                if stream_lower == '::$data': 
                    continue
                
                for ext in DANGEROUS_EXTENSIONS:
                    if ext in stream_lower:
                        print(f"[X] NGUY HIEM: Phat hien luong thuc thi an giau trong file van ban!")
                        print(f" L- File goc: {full_path}")
                        print(f" L- Luong doc hai: {stream}\n")
                
                if 'zone.identifier' in stream_lower:
                    zone_status = check_invalid_zone_id(full_path)
                    if zone_status:
                        print(f"[-] CANH BAO ZONE: {zone_status}")
                        print(f" L- File: {full_path}\n")
                        
    print("=" * 60)
    print(f"[*] Quet hoan tat. Tong so file da kiem tra: {count_files}")

if __name__ == "__main__":
    path_to_scan = input("Nhap duong dan thu muc can quet: ").strip()
    if os.path.isdir(path_to_scan):
        scan_directory(path_to_scan)
    else:
        print("[-] Duong dan khong hop le!")
