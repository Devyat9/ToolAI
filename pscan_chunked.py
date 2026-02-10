#!/usr/bin/env python3
"""
Multi-Service Scanner - Chunked Linear Processing
SSH, FTP, HTTP(S), SMB, RDP, WinRM
Con checkpoint basado en chunks procesados
"""

import socket
import asyncio
import ipaddress
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import argparse
import os
import ssl
import json

# Colors
class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    END = '\033[0m'

def print_banner():
    print(f"""{Colors.CYAN}
╔════════════════════════════════════════════╗
║   Multi-Service Scanner - CHUNKED          ║
║   SSH|FTP|Telnet|HTTP|SMB|RDP|WinRM       ║
║   Procesamiento linear con checkpoint      ║
╚════════════════════════════════════════════╝
{Colors.END}""")

def sanitize_banner(banner):
    """Limpia banners de caracteres de control y no imprimibles"""
    if not banner:
        return banner
    sanitized = ''.join(c if c.isprintable() or c in '\n\r\t' else '?' for c in str(banner))
    if len(sanitized) > 200:
        sanitized = sanitized[:200] + '...'
    return sanitized

# ============================================
# CHECKPOINT MANAGER - CHUNKED
# ============================================

class ChunkedCheckpoint:
    def __init__(self, output_dir):
        self.checkpoint_file = f"{output_dir}/.checkpoint_chunks.json"
        self.output_dir = output_dir
        self.completed_chunks = set()
        
    def exists(self):
        return os.path.exists(self.checkpoint_file)
    
    def load(self):
        """Carga checkpoint de chunks completados"""
        if not self.exists():
            return None
        
        try:
            with open(self.checkpoint_file, 'r') as f:
                data = json.load(f)
            
            self.completed_chunks = set(data.get('completed_chunks', []))
            
            print(f"{Colors.GREEN}[+] Checkpoint encontrado:{Colors.END}")
            print(f"    Timestamp: {data.get('timestamp')}")
            print(f"    Chunks completados: {len(self.completed_chunks)}/{data.get('total_chunks', 0)}")
            print(f"    Progreso: {data.get('progress_percent', 0)}%")
            
            return data
        except Exception as e:
            print(f"{Colors.RED}[!] Error cargando checkpoint: {e}{Colors.END}")
            return None
    
    def save(self, total_chunks, stats):
        """Guarda checkpoint actual"""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            
            checkpoint = {
                'timestamp': datetime.now().isoformat(),
                'completed_chunks': sorted(list(self.completed_chunks)),
                'total_chunks': total_chunks,
                'progress_percent': len(self.completed_chunks) * 100 // total_chunks if total_chunks > 0 else 0,
                'results_summary': stats
            }
            
            with open(self.checkpoint_file, 'w') as f:
                json.dump(checkpoint, f, indent=2)
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error guardando checkpoint: {e}{Colors.END}")
    
    def mark_completed(self, chunk_id):
        """Marca un chunk como completado"""
        self.completed_chunks.add(chunk_id)
    
    def is_completed(self, chunk_id):
        """Verifica si un chunk ya fue completado"""
        return chunk_id in self.completed_chunks
    
    def cleanup(self):
        """Elimina checkpoint al completar"""
        try:
            if os.path.exists(self.checkpoint_file):
                os.remove(self.checkpoint_file)
        except:
            pass

# ============================================
# CHUNK GENERATOR
# ============================================

def split_network_into_chunks(network, chunk_size=20):
    """
    Divide una red en subredes más pequeñas (chunks)
    
    Args:
        network: CIDR (ej: 172.16.0.0/12)
        chunk_size: Tamaño del chunk en bits CIDR (ej: 20 = /20 = 4096 IPs)
    
    Returns:
        Lista de (chunk_id, subnet)
    """
    net = ipaddress.ip_network(network, strict=False)
    
    # Si la red ya es más pequeña que el chunk_size, retornar como está
    if net.prefixlen >= chunk_size:
        return [(0, str(net))]
    
    # Dividir en subredes del tamaño especificado
    chunks = []
    chunk_id = 0
    for subnet in net.subnets(new_prefix=chunk_size):
        chunks.append((chunk_id, str(subnet)))
        chunk_id += 1
    
    return chunks

# ============================================
# VALIDADORES POR SERVICIO
# ============================================

def validate_ssh(ip, timeout=1):
    """SSH - Puerto 22"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 22))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        if 'SSH-' in banner:
            return True, banner
        return False, None
    except:
        return False, None

def validate_ftp(ip, timeout=1):
    """FTP - Puerto 21"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 21))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.send(b'USER anonymous\r\n')
        response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.send(b'QUIT\r\n')
        sock.close()
        if banner.startswith('220') and any(code in response for code in ['331', '530', '421']):
            return True, banner
        return False, None
    except:
        return False, None

def validate_http(ip, port, timeout=1):
    """HTTP - Puertos 80, 8000, 8080"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())
        response = sock.recv(4096).decode('utf-8', errors='ignore')
        sock.close()
        if response.startswith('HTTP/'):
            lines = response.split('\r\n')
            status_line = lines[0] if lines else ''
            server = ''
            for line in lines:
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
                    break
            info = f"{status_line} | {server}" if server else status_line
            return True, info
        return False, None
    except:
        return False, None

def validate_https(ip, port, timeout=1.5):
    """HTTPS - Puertos 443, 8443"""
    try:
        context = ssl._create_unverified_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ssl_sock = context.wrap_socket(sock, server_hostname=ip)
        ssl_sock.connect((ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        ssl_sock.send(request.encode())
        response = ssl_sock.recv(4096).decode('utf-8', errors='ignore')
        cert = ssl_sock.getpeercert()
        ssl_sock.close()
        if response.startswith('HTTP/'):
            lines = response.split('\r\n')
            status_line = lines[0]
            cn = ''
            if cert and 'subject' in cert:
                for rdn in cert['subject']:
                    for attr in rdn:
                        if attr[0] == 'commonName':
                            cn = attr[1]
            info = f"{status_line} | CN={cn}" if cn else status_line
            return True, info
        return False, None
    except:
        return False, None

def validate_smb(ip, timeout=1):
    """SMB - Puerto 445"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 445))
        negotiate = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00'
        sock.send(negotiate)
        response = sock.recv(1024)
        sock.close()
        if b'\xff\x53\x4d\x42' in response or b'\xfe\x53\x4d\x42' in response:
            version = 'SMBv2/3' if b'\xfe\x53\x4d\x42' in response else 'SMBv1'
            return True, version
        return False, None
    except:
        return False, None

def validate_rdp(ip, timeout=1):
    """RDP - Puerto 3389"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 3389))
        rdp_request = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
        sock.send(rdp_request)
        response = sock.recv(1024)
        sock.close()
        if len(response) > 11 and response[0:2] == b'\x03\x00':
            return True, 'RDP Available'
        return False, None
    except:
        return False, None

def validate_winrm(ip, port, timeout=1):
    """WinRM - Puertos 5985 (HTTP), 5986 (HTTPS)"""
    try:
        if port == 5986:
            context = ssl._create_unverified_context()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            ssl_sock = context.wrap_socket(sock)
            ssl_sock.connect((ip, port))
            request = f"POST /wsman HTTP/1.1\r\nHost: {ip}\r\nContent-Length: 0\r\n\r\n"
            ssl_sock.send(request.encode())
            response = ssl_sock.recv(1024).decode('utf-8', errors='ignore')
            ssl_sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            request = f"POST /wsman HTTP/1.1\r\nHost: {ip}\r\nContent-Length: 0\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
        if '401' in response or 'wsman' in response.lower():
            return True, f"WinRM ({'HTTPS' if port == 5986 else 'HTTP'})"
        return False, None
    except:
        return False, None

def validate_telnet(ip, timeout=2):
    """Telnet - Puerto 23"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 23))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        if banner:
            # Telnet típicamente envía banner inmediatamente
            return True, banner[:100] if len(banner) > 100 else banner
        return True, 'Telnet Available'
    except:
        return False, None

def check_port_open(ip, port, timeout=0.5):
    """Check rápido de puerto"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

# ============================================
# CONFIGURACIÓN DE SERVICIOS
# ============================================

SERVICES = {
    'ssh': {'ports': [22], 'validator': lambda ip, port: validate_ssh(ip), 'color': Colors.GREEN},
    'ftp': {'ports': [21], 'validator': lambda ip, port: validate_ftp(ip), 'color': Colors.BLUE},
    'telnet': {'ports': [23], 'validator': lambda ip, port: validate_telnet(ip), 'color': Colors.YELLOW},
    'http': {'ports': [80, 8000, 8080], 'validator': validate_http, 'color': Colors.YELLOW},
    'https': {'ports': [443, 8443], 'validator': validate_https, 'color': Colors.MAGENTA},
    'smb': {'ports': [445], 'validator': lambda ip, port: validate_smb(ip), 'color': Colors.CYAN},
    'rdp': {'ports': [3389], 'validator': lambda ip, port: validate_rdp(ip), 'color': Colors.RED},
    'winrm': {'ports': [5985, 5986], 'validator': validate_winrm, 'color': Colors.BLUE}
}

# ============================================
# WRITER
# ============================================

class ResultWriter:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.files = {}
        self.counts = {}
        for service in SERVICES.keys():
            filepath = f"{output_dir}/{service}.txt"
            self.files[service] = filepath
            self.counts[service] = 0
    
    async def write_result(self, service, ip, port, banner):
        """Escribe resultado de forma async"""
        filepath = self.files[service]
        async with asyncio.Lock():
            with open(filepath, 'a', encoding='utf-8') as f:
                clean_banner = sanitize_banner(banner)
                f.write(f"{ip}:{port} - {clean_banner}\n")
            self.counts[service] += 1
    
    def get_total(self):
        return sum(self.counts.values())

# ============================================
# SCANNER
# ============================================

async def scan_host_async(ip, semaphore, writer, enabled_services):
    """Escanea un host de forma async"""
    async with semaphore:
        loop = asyncio.get_event_loop()
        for service_name in enabled_services:
            service = SERVICES[service_name]
            for port in service['ports']:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    is_open = await loop.run_in_executor(executor, check_port_open, ip, port, 0.5)
                if not is_open:
                    continue
                with ThreadPoolExecutor(max_workers=1) as executor:
                    is_valid, banner = await loop.run_in_executor(
                        executor, service['validator'], ip, port
                    )
                if is_valid:
                    await writer.write_result(service_name, ip, port, banner)
                    color = service['color']
                    clean_banner = sanitize_banner(banner)
                    print(f"{color}[+] {service_name.upper()}: {ip}:{port} - {clean_banner}{Colors.END}", flush=True)

async def scan_chunk(chunk_cidr, max_concurrent, writer, enabled_services):
    """Escanea un chunk completo (una subred)"""
    semaphore = asyncio.Semaphore(max_concurrent)
    
    # Expandir IPs del chunk
    net = ipaddress.ip_network(chunk_cidr, strict=False)
    ips = [str(ip) for ip in net.hosts()]
    
    # Escanear todas las IPs del chunk (async dentro del chunk)
    tasks = [scan_host_async(ip, semaphore, writer, enabled_services) for ip in ips]
    await asyncio.gather(*tasks)
    
    return len(ips)

async def scan_network_chunked(networks, max_concurrent, output_dir, enabled_services, chunk_size, resume=False):
    """Escanea redes divididas en chunks procesados linealmente"""
    writer = ResultWriter(output_dir)
    stats = {service: 0 for service in enabled_services}
    checkpoint = ChunkedCheckpoint(output_dir)
    
    # Cargar checkpoint si existe
    if resume and checkpoint.exists():
        checkpoint.load()
    
    # Generar todos los chunks
    all_chunks = []
    for network in networks:
        chunks = split_network_into_chunks(network, chunk_size)
        all_chunks.extend(chunks)
    
    total_chunks = len(all_chunks)
    print(f"{Colors.BLUE}[*] Total de chunks: {total_chunks}{Colors.END}", flush=True)
    print(f"{Colors.BLUE}[*] Chunk size: /{chunk_size} (~{2**(32-chunk_size):,} IPs por chunk){Colors.END}", flush=True)
    print(f"{Colors.BLUE}[*] Servicios: {', '.join(enabled_services)}{Colors.END}", flush=True)
    print(f"{Colors.BLUE}[*] Threads por chunk: {max_concurrent}{Colors.END}", flush=True)
    print(f"{Colors.YELLOW}[*] Output: {output_dir}{Colors.END}\n", flush=True)
    
    # Procesar chunks linealmente
    start_time = datetime.now()
    processed_chunks = 0
    
    for chunk_id, chunk_cidr in all_chunks:
        # Skip si ya está completado
        if checkpoint.is_completed(chunk_id):
            processed_chunks += 1
            continue
        
        chunk_start = datetime.now()
        
        # Mostrar progreso
        percent = (processed_chunks * 100) // total_chunks if total_chunks > 0 else 0
        print(f"\n{Colors.CYAN}[*] Chunk {processed_chunks+1}/{total_chunks} ({percent}%) - {chunk_cidr}{Colors.END}", flush=True)
        
        # Escanear chunk completo
        ips_scanned = await scan_chunk(chunk_cidr, max_concurrent, writer, enabled_services)
        
        # Marcar como completado y guardar checkpoint
        checkpoint.mark_completed(chunk_id)
        stats = {service: writer.counts[service] for service in enabled_services}
        checkpoint.save(total_chunks, stats)
        
        processed_chunks += 1
        chunk_elapsed = datetime.now() - chunk_start
        
        print(f"{Colors.GREEN}[✓] Chunk completado - {ips_scanned} IPs en {chunk_elapsed} | Total encontrados: {writer.get_total()}{Colors.END}", flush=True)
    
    elapsed = datetime.now() - start_time
    print(f"\n{Colors.GREEN}[+] Escaneo completado en {elapsed}{Colors.END}\n", flush=True)
    
    # Limpiar checkpoint
    checkpoint.cleanup()
    
    return writer, stats

# ============================================
# REPORT
# ============================================

def generate_report(writer, output_dir, elapsed, enabled_services):
    report_file = f"{output_dir}/REPORT.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("Multi-Service Scan Report (Chunked)\n")
        f.write(f"Timestamp: {datetime.now()}\n")
        f.write(f"Elapsed: {elapsed}\n")
        f.write("="*60 + "\n\n")
        for service in enabled_services:
            f.write(f"=== {service.upper()} ===\n")
            filepath = writer.files[service]
            if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                with open(filepath, 'r', encoding='utf-8') as sf:
                    f.write(sf.read())
            else:
                f.write("None found\n")
            f.write(f"Total: {writer.counts[service]}\n\n")
        f.write("=== SUMMARY ===\n")
        for service in enabled_services:
            f.write(f"{service.upper()}: {writer.counts[service]}\n")
        f.write(f"TOTAL: {writer.get_total()}\n")
    return report_file

def parse_targets(args):
    """Parsea targets desde múltiples fuentes"""
    targets = []
    if args.input_list:
        try:
            with open(args.input_list, 'r') as f:
                file_targets = [line.strip() for line in f 
                               if line.strip() and not line.startswith('#')]
                targets.extend(file_targets)
                print(f"{Colors.GREEN}[+] Cargados desde {args.input_list}: {len(file_targets)}{Colors.END}")
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Archivo no encontrado: {args.input_list}{Colors.END}")
            sys.exit(1)
    if args.targets:
        targets.extend(args.targets)
        print(f"{Colors.GREEN}[+] Targets desde CLI: {len(args.targets)}{Colors.END}")
    if not targets:
        print(f"{Colors.RED}[!] No se especificaron targets{Colors.END}")
        sys.exit(1)
    return targets

# ============================================
# MAIN
# ============================================

def main():
    parser = argparse.ArgumentParser(
        description='Multi-Service Scanner - Chunked Linear Processing',
        epilog="""
Ejemplos:
  %(prog)s -iL targets.txt
  %(prog)s 172.16.0.0/12 -c 20 -t 1000
  %(prog)s -iL targets.txt --resume  # Reanudar desde último chunk
  %(prog)s 10.0.0.0/8 -c 18 -t 2000  # Chunks más grandes
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('targets', nargs='*', help='IPs o rangos CIDR')
    parser.add_argument('-iL', '--input-list', metavar='FILE', help='Archivo con lista de IPs/CIDRs')
    parser.add_argument('-t', '--threads', type=int, default=1000, metavar='NUM',
                       help='Threads concurrentes por chunk (default: 1000)')
    parser.add_argument('-c', '--chunk-size', type=int, default=20, metavar='BITS',
                       help='Tamaño de chunk en bits CIDR (default: 20 = /20 = 4096 IPs)')
    parser.add_argument('-s', '--services', default='all', metavar='SERVICES',
                       help='Servicios: all, ssh, ftp, telnet, http, https, smb, rdp, winrm')
    parser.add_argument('-o', '--output', metavar='DIR',
                       help='Directorio de salida (default: scan_TIMESTAMP)')
    parser.add_argument('--resume', action='store_true',
                       help='Reanudar desde último chunk completado')
    
    args = parser.parse_args()
    print_banner()
    
    # Parsear servicios
    if args.services == 'all':
        enabled_services = list(SERVICES.keys())
    else:
        enabled_services = [s.strip().lower() for s in args.services.split(',')]
        invalid = [s for s in enabled_services if s not in SERVICES]
        if invalid:
            print(f"{Colors.RED}[!] Servicios inválidos: {', '.join(invalid)}{Colors.END}")
            sys.exit(1)
    
    # Parsear targets
    targets = parse_targets(args)
    print(f"{Colors.GREEN}[+] Total de targets: {len(targets)}{Colors.END}")
    
    # Output dir
    output_dir = args.output or f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Verificar checkpoint
    checkpoint_file = f"{output_dir}/.checkpoint_chunks.json"
    if not args.resume and os.path.exists(checkpoint_file):
        print(f"{Colors.YELLOW}[!] Checkpoint existente encontrado en {output_dir}{Colors.END}")
        resp = input(f"{Colors.CYAN}¿Reanudar escaneo anterior? [y/N]: {Colors.END}").strip().lower()
        args.resume = (resp == 'y')
    
    # Scan
    start_time = datetime.now()
    try:
        writer, stats = asyncio.run(scan_network_chunked(
            targets, args.threads, output_dir, enabled_services, args.chunk_size, args.resume
        ))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrumpido - Checkpoint guardado{Colors.END}", flush=True)
        print(f"{Colors.CYAN}[*] Para reanudar: {sys.argv[0]} --resume -o {output_dir}{Colors.END}", flush=True)
        sys.exit(0)
    
    elapsed = datetime.now() - start_time
    
    # Report
    report_file = generate_report(writer, output_dir, elapsed, enabled_services)
    
    # Summary
    print(f"\n{Colors.CYAN}╔════════════════════════════════════════╗{Colors.END}", flush=True)
    print(f"{Colors.CYAN}║         SCAN COMPLETADO                 ║{Colors.END}", flush=True)
    print(f"{Colors.CYAN}╚════════════════════════════════════════╝{Colors.END}\n", flush=True)
    
    for service in enabled_services:
        count = writer.counts.get(service, 0)
        if count > 0:
            color = SERVICES[service]['color']
            print(f"{color}[+] {service.upper()}: {count}{Colors.END}", flush=True)
    
    print(f"\n{Colors.BLUE}[*] Tiempo: {elapsed}{Colors.END}", flush=True)
    print(f"{Colors.YELLOW}[*] Archivos: {output_dir}/*.txt{Colors.END}", flush=True)
    print(f"{Colors.YELLOW}[*] Reporte: {report_file}{Colors.END}\n", flush=True)

if __name__ == '__main__':
    main()
