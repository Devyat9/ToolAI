# Se entrega un listado de IP (ips.txt) en donde se tiene:
#  10.0.0.1
#  10.0.0.2
#  10.2.0.3
#  192.168.0.1
#  192.168.0.10
#  192.168.100.5
# con este script se obtiene:
#  10.0.0.0/24
#  10.2.0.0/24
#  192.168.0.0/24
#  192.168.100.0/24


import sys
import os

def extract_segments(input_file, output_file=None):
    try:
        with open(input_file, 'r') as file:
            ips = file.readlines()

        # Extraer los segmentos /24
        segments = set()
        for ip in ips:
            ip = ip.strip()
            if ip:
                # Tomar solo los primeros tres octetos para formar el segmento /24
                segments.add('.'.join(ip.split('.')[:3]) + '.0/24')

        # Convertir el conjunto a una lista ordenada
        segments = sorted(segments)

        # Mostrar los segmentos por pantalla
        for segment in segments:
            print(segment)

        # Guardar en archivo si se especifica
        if output_file:
            with open(output_file, 'w') as file:
                for segment in segments:
                    file.write(segment + '\n')
            print(f"Segmentos guardados en {output_file}")

    except FileNotFoundError:
        print(f"Error: El archivo {input_file} no existe.")
    except Exception as e:
        print(f"Error: {e}")

def main():
    if len(sys.argv) < 2:
        print("Uso: python script.py <archivo_entrada> [-o <archivo_salida>]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = None

    if '-o' in sys.argv:
        try:
            output_file = sys.argv[sys.argv.index('-o') + 1]
        except IndexError:
            print("Error: Debes especificar un archivo de salida después de '-o'.")
            sys.exit(1)

    extract_segments(input_file, output_file)

if __name__ == "__main__":
    main()
