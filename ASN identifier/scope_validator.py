#!/usr/bin/env python3

import argparse
import ipaddress
import subprocess
import time
import sys
import signal
import json
import os
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import re

@dataclass
class WhoisBlock:
    cidr: str
    owner: str
    country: str
    network: ipaddress.IPv4Network = None
    
    def __post_init__(self):
        if self.network is None:
            try:
                self.network = ipaddress.IPv4Network(self.cidr, strict=False)
            except:
                pass

class ScopeValidator:
    def __init__(self, domain: str, delay: float = 1.0, retry: int = 3, checkpoint_file: str = "checkpoint.json"):
        self.domain = domain.upper()
        self.delay = delay
        self.retry = retry
        self.checkpoint_file = checkpoint_file
        
        # Cache optimizado: índice por primer octeto
        self.cache_by_octets: Dict[int, List[WhoisBlock]] = defaultdict(list)
        
        self.results: Dict[str, List[Tuple[str, str]]] = {}
        self.out_of_scope: Dict[str, List[Tuple[str, str]]] = {}
        self.errors: List[str] = []
        self.total_queries = 0
        self.cache_hits = 0
        self.processed_ips: Set[str] = set()
        
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, sig, frame):
        print("\n\n[!] Ctrl+C detectado. Guardando checkpoint...")
        self.save_checkpoint()
        print(f"[+] Checkpoint guardado en: {self.checkpoint_file}")
        print("[*] Para reanudar: python3 script.py -iL <file> -o <output> -d <domain> --resume")
        sys.exit(0)
    
    def add_to_cache(self, block: WhoisBlock):
        """Agrega bloque al cache indexado"""
        if block.network is None:
            return
        
        # Indexar por primer octeto del bloque
        first_octet = int(block.network.network_address) >> 24
        self.cache_by_octets[first_octet].append(block)
    
    def save_checkpoint(self):
        """Guarda estado actual"""
        # Serializar cache plano para JSON
        all_blocks = []
        for blocks in self.cache_by_octets.values():
            for block in blocks:
                all_blocks.append({
                    'cidr': block.cidr,
                    'owner': block.owner,
                    'country': block.country
                })
        
        checkpoint = {
            'processed_ips': list(self.processed_ips),
            'all_blocks_cache': all_blocks,
            'results': self.results,
            'out_of_scope': self.out_of_scope,
            'errors': self.errors,
            'total_queries': self.total_queries,
            'cache_hits': self.cache_hits
        }
        with open(self.checkpoint_file, 'w') as f:
            json.dump(checkpoint, f, indent=2)
    
    def load_checkpoint(self) -> bool:
        """Carga checkpoint si existe"""
        if not os.path.exists(self.checkpoint_file):
            return False
        
        try:
            with open(self.checkpoint_file, 'r') as f:
                checkpoint = json.load(f)
            
            self.processed_ips = set(checkpoint['processed_ips'])
            
            # Reconstruir cache indexado
            for block_data in checkpoint['all_blocks_cache']:
                block = WhoisBlock(
                    cidr=block_data['cidr'],
                    owner=block_data['owner'],
                    country=block_data['country']
                )
                self.add_to_cache(block)
            
            self.results = checkpoint['results']
            self.out_of_scope = checkpoint['out_of_scope']
            self.errors = checkpoint['errors']
            self.total_queries = checkpoint['total_queries']
            self.cache_hits = checkpoint['cache_hits']
            
            print(f"[+] Checkpoint cargado: {len(self.processed_ips)} IPs ya procesadas")
            return True
        except Exception as e:
            print(f"[!] Error cargando checkpoint: {e}", file=sys.stderr)
            return False
    
    def load_predefined_ranges(self, ranges_dir: str = "."):
        """Carga rangos predefinidos de CDNs/Cloud providers"""
        providers = {
            'amazon-range.txt': 'Amazon Technologies Inc.',
            'google.txt': 'Google LLC',
            'cloudflare.txt': 'Cloudflare, Inc.',
            'akamai.txt': 'Akamai Technologies',
            'imperva.txt': 'Imperva Inc.'
        }
        
        loaded = 0
        for filename, owner in providers.items():
            filepath = os.path.join(ranges_dir, filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                block = WhoisBlock(cidr=line, owner=owner, country="N/A")
                                self.add_to_cache(block)
                                loaded += 1
                except Exception as e:
                    print(f"[!] Error cargando {filename}: {e}", file=sys.stderr)
        
        if loaded > 0:
            print(f"[+] Pre-cargados {loaded} rangos de proveedores conocidos")
    
    def parse_ip_or_cidr(self, line: str) -> Optional[ipaddress.IPv4Network]:
        """Parsea IP o CIDR a objeto de red"""
        line = line.strip()
        if not line:
            return None
            
        try:
            if '/' not in line:
                return ipaddress.IPv4Network(f"{line}/32", strict=False)
            else:
                return ipaddress.IPv4Network(line, strict=False)
        except (ipaddress.AddressValueError, ValueError):
            return None
    
    def find_in_cache(self, network: ipaddress.IPv4Network) -> Optional[WhoisBlock]:
        """Busca si la red está dentro de algún bloque cacheado (optimizado)"""
        # Obtener primer octeto de la IP a buscar
        first_octet = int(network.network_address) >> 24
        
        # Solo buscar en bloques del mismo primer octeto y adyacentes
        # (un bloque /8 puede abarcar todo el octeto)
        octets_to_check = [first_octet]
        
        # Buscar en cache indexado
        for octeto in octets_to_check:
            if octeto in self.cache_by_octets:
                for block in self.cache_by_octets[octeto]:
                    try:
                        if network.subnet_of(block.network) or network == block.network:
                            return block
                    except:
                        continue
        
        # Fallback: buscar en todos los bloques si no se encontró
        # (para casos donde el bloque abarca múltiples octetos)
        for blocks in self.cache_by_octets.values():
            for block in blocks:
                try:
                    if network.subnet_of(block.network) or network == block.network:
                        # Agregar a índice del octeto actual para futuros hits
                        if first_octet not in self.cache_by_octets or block not in self.cache_by_octets[first_octet]:
                            self.cache_by_octets[first_octet].append(block)
                        return block
                except:
                    continue
        
        return None
    
    def query_whois_with_referral(self, ip_or_cidr: str) -> Optional[WhoisBlock]:
        """Consulta whois siguiendo referrals"""
        for attempt in range(self.retry):
            try:
                result = self._whois_subprocess(ip_or_cidr)
                if result:
                    return result
                    
            except Exception:
                if attempt < self.retry - 1:
                    time.sleep(self.delay * (attempt + 1))
                    continue
                else:
                    return None
        
        return None
    
    def _whois_subprocess(self, target: str) -> Optional[WhoisBlock]:
        """Ejecuta whois via subprocess siguiendo referrals"""
        try:
            if '/' in target:
                target = target.split('/')[0]
            
            result = subprocess.run(
                ['whois', target],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode != 0:
                return None
            
            output = result.stdout
            
            # Verificar referral
            referral_match = re.search(r'ReferralServer:\s+whois://([^\s]+)', output)
            if referral_match:
                referral_server = referral_match.group(1)
                
                result2 = subprocess.run(
                    ['whois', '-h', referral_server, target],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                
                if result2.returncode == 0:
                    output = result2.stdout
            
            # Parsear
            parsed = self._parse_lacnic_whois(output)
            if parsed:
                return parsed
                
            parsed = self._parse_arin_whois(output)
            if parsed:
                return parsed
                
            parsed = self._parse_ripe_whois(output)
            if parsed:
                return parsed
            
            return None
            
        except subprocess.TimeoutExpired:
            return None
        except FileNotFoundError:
            print("[!] Error: comando 'whois' no encontrado", file=sys.stderr)
            return None
        except Exception:
            return None
    
    def _parse_arin_whois(self, whois_output: str) -> Optional[WhoisBlock]:
        """Parsea output de whois ARIN"""
        cidr = None
        netrange = None
        org_name = None
        country = None
        
        if 'ReferralServer:' in whois_output and 'NetType:' in whois_output:
            if 'Transferred to LACNIC' in whois_output or 'Transferred to RIPE' in whois_output:
                return None
        
        for line in whois_output.split('\n'):
            line = line.strip()
            
            if line.startswith('CIDR:'):
                cidr_raw = line.split(':', 1)[1].strip()
                cidr = cidr_raw.split(',')[0].strip()
            elif line.startswith('NetRange:'):
                netrange = line.split(':', 1)[1].strip()
            elif line.startswith('OrgName:'):
                org_name = line.split(':', 1)[1].strip()
            elif line.startswith('Country:'):
                country = line.split(':', 1)[1].strip()
        
        if not cidr and netrange:
            cidr = self._netrange_to_cidr(netrange)
        
        if cidr and org_name:
            return WhoisBlock(cidr=cidr, owner=org_name, country=country or "N/A")
        
        return None
    
    def _parse_lacnic_whois(self, whois_output: str) -> Optional[WhoisBlock]:
        """Parsea output de whois LACNIC"""
        inetnum = None
        owner = None
        country = None
        
        for line in whois_output.split('\n'):
            line = line.strip()
            
            if line.startswith('inetnum:'):
                inetnum = line.split(':', 1)[1].strip()
            elif line.startswith('owner:'):
                owner = line.split(':', 1)[1].strip()
            elif line.startswith('country:'):
                country = line.split(':', 1)[1].strip()
        
        if inetnum and owner:
            return WhoisBlock(cidr=inetnum, owner=owner, country=country or "N/A")
        
        return None
    
    def _parse_ripe_whois(self, whois_output: str) -> Optional[WhoisBlock]:
        """Parsea output de whois RIPE/APNIC/AFRINIC"""
        inetnum = None
        netname = None
        org_name = None
        country = None
        
        for line in whois_output.split('\n'):
            line = line.strip()
            
            if line.startswith('inetnum:'):
                inetnum_raw = line.split(':', 1)[1].strip()
                inetnum = self._netrange_to_cidr(inetnum_raw)
            elif line.startswith('netname:'):
                netname = line.split(':', 1)[1].strip()
            elif line.startswith('org-name:'):
                org_name = line.split(':', 1)[1].strip()
            elif line.startswith('descr:') and not org_name:
                org_name = line.split(':', 1)[1].strip()
            elif line.startswith('country:'):
                country = line.split(':', 1)[1].strip()
        
        owner = org_name if org_name else netname
        
        if inetnum and owner:
            return WhoisBlock(cidr=inetnum, owner=owner, country=country or "N/A")
        
        return None
    
    def _netrange_to_cidr(self, netrange: str) -> Optional[str]:
        """Convierte NetRange a CIDR"""
        try:
            if ' - ' in netrange:
                start_ip, end_ip = netrange.split(' - ')
                start = ipaddress.IPv4Address(start_ip.strip())
                end = ipaddress.IPv4Address(end_ip.strip())
                networks = list(ipaddress.summarize_address_range(start, end))
                if networks:
                    return str(networks[0])
            else:
                return netrange.strip()
        except Exception:
            return None
        
        return None
    
    def matches_domain(self, owner: str) -> bool:
        """Verifica si owner contiene el dominio"""
        return self.domain in owner.upper()
    
    def classify_ip(self, line: str, network: ipaddress.IPv4Network):
        """Clasifica una IP según cache o nueva consulta"""
        cached_block = self.find_in_cache(network)
        
        if cached_block:
            self.cache_hits += 1
            
            if self.matches_domain(cached_block.owner):
                if cached_block.owner not in self.results:
                    self.results[cached_block.owner] = []
                self.results[cached_block.owner].append((str(network), cached_block.cidr))
                print(f"  → Cached (IN SCOPE): {cached_block.owner} ({cached_block.cidr})")
            else:
                if cached_block.owner not in self.out_of_scope:
                    self.out_of_scope[cached_block.owner] = []
                self.out_of_scope[cached_block.owner].append((str(network), cached_block.cidr))
                print(f"  → Cached (Fuera): {cached_block.owner} ({cached_block.cidr})")
            return
        
        print(f"  → Consultando whois...")
        self.total_queries += 1
        
        whois_result = self.query_whois_with_referral(line)
        
        if whois_result:
            self.add_to_cache(whois_result)
            
            if self.matches_domain(whois_result.owner):
                if whois_result.owner not in self.results:
                    self.results[whois_result.owner] = []
                self.results[whois_result.owner].append((str(network), whois_result.cidr))
                print(f"  ✓ IN SCOPE: {whois_result.owner} ({whois_result.cidr})")
            else:
                if whois_result.owner not in self.out_of_scope:
                    self.out_of_scope[whois_result.owner] = []
                self.out_of_scope[whois_result.owner].append((str(network), whois_result.cidr))
                print(f"  ✗ Fuera: {whois_result.owner} ({whois_result.cidr})")
        else:
            self.errors.append(line)
            print(f"  ✗ Error en consulta")
    
    def process_file(self, input_file: str):
        """Procesa archivo de entrada"""
        try:
            with open(input_file, 'r') as f:
                lines = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Error: archivo '{input_file}' no encontrado", file=sys.stderr)
            sys.exit(1)
        
        total = len(lines)
        processed_count = len(self.processed_ips)
        
        print(f"[*] Total de entradas: {total}")
        if processed_count > 0:
            print(f"[*] Ya procesadas: {processed_count}")
        print()
        
        for idx, line in enumerate(lines, 1):
            if line in self.processed_ips:
                continue
            
            network = self.parse_ip_or_cidr(line)
            
            if not network:
                self.errors.append(line)
                print(f"[{idx}/{total}] {line}", file=sys.stderr)
                print(f"  [!] Error parseando", file=sys.stderr)
                self.processed_ips.add(line)
                continue
            
            print(f"[{idx}/{total}] {line}")
            self.classify_ip(line, network)
            self.processed_ips.add(line)
            
            if len(self.processed_ips) % 50 == 0:
                self.save_checkpoint()
            
            if idx < total:
                time.sleep(self.delay)
    
    def generate_report(self) -> str:
        """Genera reporte formateado"""
        report = []
        report.append("=" * 80)
        report.append(f"VALIDACIÓN DE SCOPE - DOMINIO: {self.domain}")
        report.append("=" * 80)
        report.append("")
        
        if self.results:
            report.append("=" * 80)
            report.append("IN SCOPE")
            report.append("=" * 80)
            for owner in sorted(self.results.keys()):
                report.append(f"\n=== {owner} ===")
                
                blocks = set()
                for _, parent_block in self.results[owner]:
                    blocks.add(parent_block)
                
                report.append(f"Bloques principales: {', '.join(sorted(blocks))}")
                report.append("")
                report.append("IPs/Segmentos dentro:")
                
                for ip_cidr, parent_block in sorted(self.results[owner]):
                    report.append(f"  - {ip_cidr} → dentro de {parent_block}")
                
                report.append("")
        
        if self.out_of_scope:
            report.append("=" * 80)
            report.append("FUERA DE SCOPE")
            report.append("=" * 80)
            for owner in sorted(self.out_of_scope.keys()):
                blocks = set()
                for _, parent_block in self.out_of_scope[owner]:
                    blocks.add(parent_block)
                
                report.append(f"\n--- {owner} ---")
                report.append(f"Bloques: {', '.join(sorted(blocks))}")
                report.append("IPs/Segmentos:")
                for ip_cidr, parent_block in sorted(self.out_of_scope[owner]):
                    report.append(f"  - {ip_cidr} → dentro de {parent_block}")
            report.append("")
        
        if self.errors:
            report.append("=" * 80)
            report.append("ERRORES")
            report.append("=" * 80)
            for item in sorted(self.errors):
                report.append(f"  - {item}")
            report.append("")
        
        report.append("=" * 80)
        report.append("ESTADÍSTICAS")
        report.append("=" * 80)
        
        total_in_scope = sum(len(items) for items in self.results.values())
        total_out_of_scope = sum(len(items) for items in self.out_of_scope.values())
        
        report.append(f"Total en scope: {total_in_scope}")
        report.append(f"Total fuera de scope: {total_out_of_scope}")
        report.append(f"Total con errores: {len(self.errors)}")
        report.append(f"Consultas whois realizadas: {self.total_queries}")
        report.append(f"Hits de caché: {self.cache_hits}")
        report.append(f"Organizaciones en scope: {len(self.results)}")
        report.append(f"Organizaciones fuera de scope: {len(self.out_of_scope)}")
        
        total_processed = total_in_scope + total_out_of_scope
        if total_processed > 0:
            efficiency = (self.cache_hits / total_processed) * 100
            report.append(f"Eficiencia de caché: {efficiency:.1f}%")
        
        report.append("")
        
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(
        description='Validador de scope para IPs públicas basado en whois',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-iL', '--input-list', required=True,
                        help='Archivo con lista de IPs/CIDRs')
    parser.add_argument('-o', '--output', required=True,
                        help='Archivo de salida para el reporte')
    parser.add_argument('-d', '--domain', required=True,
                        help='Dominio/organización a buscar')
    parser.add_argument('--delay', type=float, default=1.0,
                        help='Delay entre consultas whois (default: 1.0s)')
    parser.add_argument('--retry', type=int, default=3,
                        help='Reintentos para consultas fallidas (default: 3)')
    parser.add_argument('--resume', action='store_true',
                        help='Reanudar desde checkpoint anterior')
    parser.add_argument('--checkpoint', default='checkpoint.json',
                        help='Archivo de checkpoint (default: checkpoint.json)')
    parser.add_argument('--ranges-dir', default='.',
                        help='Directorio con rangos predefinidos (default: .)')
    
    args = parser.parse_args()
    
    if args.delay < 0:
        print("[!] Error: --delay debe ser >= 0", file=sys.stderr)
        sys.exit(1)
    if args.retry < 1:
        print("[!] Error: --retry debe ser >= 1", file=sys.stderr)
        sys.exit(1)
    
    validator = ScopeValidator(
        domain=args.domain,
        delay=args.delay,
        retry=args.retry,
        checkpoint_file=args.checkpoint
    )
    
    print(f"[*] Dominio objetivo: {args.domain}")
    print(f"[*] Configuración: delay={args.delay}s, retry={args.retry}")
    
    validator.load_predefined_ranges(args.ranges_dir)
    
    if args.resume:
        if not validator.load_checkpoint():
            print("[!] No se encontró checkpoint, iniciando desde cero")
    
    print()
    
    start_time = time.time()
    validator.process_file(args.input_list)
    elapsed = time.time() - start_time
    
    validator.save_checkpoint()
    
    print("\n")
    report = validator.generate_report()
    print(report)
    
    try:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"[+] Reporte guardado en: {args.output}")
        print(f"[+] Checkpoint guardado en: {args.checkpoint}")
        print(f"[+] Tiempo total: {elapsed:.2f} segundos")
    except Exception as e:
        print(f"[!] Error escribiendo archivo: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
