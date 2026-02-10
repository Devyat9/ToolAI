#!/usr/bin/env python3
import argparse
import ipaddress
import sys
import re

def netmask_to_cidr(netmask):
    """Convierte máscara decimal a prefijo CIDR"""
    return ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen

def is_private_network(network):
    """Verifica si el segmento es privado"""
    return network.is_private

def parse_ip_mask(line):
    """
    Parse líneas en formato:
    - IP/MASK (10.1.124.1/255.255.252.0)
    - IP MASK (1.2.3.1 255.255.255.252)
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    # Formato: IP/MASK
    if '/' in line:
        parts = line.split('/')
        if len(parts) == 2:
            ip = parts[0].strip()
            mask = parts[1].strip()
            # Si la máscara ya es CIDR, retornarla
            if mask.isdigit():
                return f"{ip}/{mask}"
            return ip, mask
    
    # Formato: IP MASK (separado por espacio)
    parts = re.split(r'\s+', line)
    if len(parts) >= 2:
        return parts[0], parts[1]
    
    return None

def convert_to_network(ip, netmask):
    """Convierte IP y máscara a segmento de red en formato CIDR"""
    try:
        # Si netmask es dígito, ya es CIDR
        if str(netmask).isdigit():
            cidr = int(netmask)
        else:
            cidr = netmask_to_cidr(netmask)
        
        # Crear el objeto de red y obtener la dirección de red
        interface = ipaddress.IPv4Interface(f'{ip}/{cidr}')
        network = interface.network
        
        return network
    except Exception as e:
        print(f"Error procesando {ip}/{netmask}: {e}", file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser(
        description='Convierte IPs con máscaras a segmentos CIDR',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Ejemplos:
  %(prog)s -i input.txt -o output.txt
  %(prog)s -i input.txt -o output.txt --only-private
  cat ips.txt | %(prog)s -o output.txt
  %(prog)s --only-private < ips.txt > networks.txt

Formatos de entrada soportados:
  10.1.124.1/255.255.252.0
  1.2.3.1 255.255.255.252
  192.168.1.5/24
        '''
    )
    
    parser.add_argument('-i', '--input', 
                       help='Archivo de entrada (default: stdin)')
    parser.add_argument('-o', '--output', 
                       help='Archivo de salida (default: stdout)')
    parser.add_argument('-op', '--only-private', 
                       action='store_true',
                       help='Solo incluir segmentos privados (RFC 1918)')
    parser.add_argument('-u', '--unique', 
                       action='store_true',
                       help='Eliminar duplicados')
    
    args = parser.parse_args()
    
    # Abrir entrada
    if args.input:
        try:
            input_file = open(args.input, 'r')
        except Exception as e:
            print(f"Error abriendo {args.input}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        input_file = sys.stdin
    
    networks = []
    
    # Procesar líneas
    for line in input_file:
        parsed = parse_ip_mask(line)
        if not parsed:
            continue
        
        if isinstance(parsed, str):
            # Ya está en formato CIDR
            try:
                network = ipaddress.IPv4Network(parsed, strict=False)
                networks.append(network)
            except Exception as e:
                print(f"Error procesando {line.strip()}: {e}", file=sys.stderr)
        else:
            ip, mask = parsed
            network = convert_to_network(ip, mask)
            if network:
                networks.append(network)
    
    if input_file != sys.stdin:
        input_file.close()
    
    # Filtrar privadas si se solicitó
    if args.only_private:
        networks = [net for net in networks if is_private_network(net)]
    
    # Eliminar duplicados si se solicitó
    if args.unique:
        networks = list(set(networks))
        networks.sort()
    
    # Escribir salida
    if args.output:
        try:
            output_file = open(args.output, 'w')
        except Exception as e:
            print(f"Error creando {args.output}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        output_file = sys.stdout
    
    for network in networks:
        output_file.write(f"{network}\n")
    
    if output_file != sys.stdout:
        output_file.close()
        print(f"✓ Procesados {len(networks)} segmentos → {args.output}", file=sys.stderr)

if __name__ == '__main__':
    main()
