import sys

def arpa_to_ip(arpa_entry):
    # Quita el sufijo .in-addr.arpa
    sin_sufijo = arpa_entry.strip().replace('.in-addr.arpa', '')
    # Invierte el orden de los octetos
    octetos = sin_sufijo.split('.')
    ip = '.'.join(octetos[::-1])
    return ip

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} archivo_entrada.txt")
        sys.exit(1)
    
    archivo_entrada = sys.argv[1]

    with open(archivo_entrada, 'r') as f:
        for linea in f:
            if linea.strip():
                ip_convertida = arpa_to_ip(linea)
                print(ip_convertida)
