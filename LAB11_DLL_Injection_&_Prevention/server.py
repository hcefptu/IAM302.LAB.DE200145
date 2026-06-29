import socket

def main():
    host = '0.0.0.0'
    port = 8080

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"[*] C2 Server đang lắng nghe trên {host}:{port}...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"[+] Nhận kết nối từ {addr}")
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                print("[+] Dữ liệu nhận được:")
                print(data.decode('utf-8', errors='ignore'))
        except:
            pass
        finally:
            client_socket.close()
            print(f"[-] Kết nối từ {addr} đã đóng.")

if __name__ == '__main__':
    main()
