import sys
import ipaddress

def generar_ips_privadas(base):
    if not base.isdigit() or int(base) < 0 or int(base) > 255:
        print("Error: El primer octeto debe ser un número entre 0 y 255.")
        return

    base_octeto = int(base)

    for i in range(1, 256):
        for j in range(1, 256):
            ip = f"{base_octeto}.{i}.{j}.1"
            if ipaddress.ip_address(ip).is_private:
                print(ip)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 generar_ips.py <primer_octeto>")
        print("Ejemplo: python3 generar_ips.py 10")
    else:
        generar_ips_privadas(sys.argv[1])
