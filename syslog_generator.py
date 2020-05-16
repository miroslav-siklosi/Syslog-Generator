"""
Cisco ASA Syslogs Generator for Anomaly Detection

MIT License

Copyright (c) 2020 Miroslav Siklosi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import datetime
import random
from faker import Faker
import argparse

class logTemplates:
    anomalous_messages = [
        "%ASA-2-106017: Deny IP due to Land Attack from {source_address} to {dest_address}.",
        "%ASA-1-106021: Deny protocol reverse path check from {source_address} to {dest_address} on interface {interface_name}.", 
        "%ASA-1-107002: RIP pkt failed from {source_address} : version=2 on interface {interface_name}",        
        "%ASA-2-108003: Terminating ESMTP connection; malicious pattern detected in the mail address from {interface_name}:{source_address}/{source_port} to {interface_name}:{dest_address}/{dest_port}.",
        "%ASA-4-109017: User at {source_address} exceeded auth proxy connection limit (1000).",
        "%ASA-2-201003: Embryonic limit exceeded 748/500 for {remote_address}/{dest_port} 8.8.8.8 {local_address}/{source_port} on interface {interface_name}.",
        "%ASA-6-201012: Per-client embryonic connection limit exceeded curr 135/100 for input packet from {source_address}/{source_port} to {dest_address}/{dest_port} on interface {interface_name}.",       
        "%ASA-4-209003: Fragment database limit of number exceeded: src = {source_address} , dest = {dest_address} , proto = UDP , id = {number}",
        "%ASA-4-209003: Fragment database limit of number exceeded: src = {source_address} , dest = {dest_address} , proto = ICMP , id = {number}",
        "%ASA-3-322001: Deny MAC address {MAC_address}, possible spoof attempt on interface {interface_name}",
        "%ASA-3-322002: ARP inspection check failed for arp request received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is statically bound to MAC Address {MAC_address}.",
        "%ASA-3-322002: ARP inspection check failed for arp request received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is dynamically bound to MAC Address {MAC_address}.",
        "%ASA-3-322002: ARP inspection check failed for arp response received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is statically bound to MAC Address {MAC_address}.",        
        "%ASA-4-400007: IPS:1100 IP Fragment Attack from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400008: IPS:1102 IP Impossible Packet from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400009: IPS:1103 IP Fragments Overlap from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400023: IPS:2150 Fragmented ICMP Traffic from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400024: IPS:2151 Large ICMP Traffic from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400025: IPS:2154 Ping of Death Attack from {source_address} to {dest_address} on interface {interface_name}",        
        "%ASA-4-400027: IPS:3041 TCP SYN+FIN flags from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400028: IPS:3042 TCP FIN only flags from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400029: IPS:3153 FTP Improper Address Specified from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400030: IPS:3154 FTP Improper Port Specified from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400033: IPS:4052 UDP Chargen DoS attack from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400041: IPS:6103 Proxied RPC Request from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400050: IPS:6190 statd Buffer Overflow from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-5-402128: CRYPTO: An attempt to allocate a large memory block failed, size: 300000000 , limit: 100000000",        
        "%ASA-4-405001: Received ARP response collision from {source_address}/{MAC_address} on interface {interface_name} with existing ARP entry {dest_address}/{MAC_address}.",
        "%ASA-4-405002: Received mac mismatch collision from {source_address}/{MAC_address} for authenticated host",
        "%ASA-2-410002: Dropped num DNS responses with mis-matched id in the past 10 second(s): from {interface_name}:{source_address}/{source_port} to {interface_name}:{dest_address}/{dest_port}",
        "%ASA-4-419002: Received duplicate TCP SYN from {interface_name}:{source_address}/{source_port} to {interface_name}:{dest_address}/{dest_port} with different initial sequence number.",
        "%ASA-6-605004: Login denied from {source_address}/{source_port} to {interface_name}:{dest_address}/{service} for user {user}",        
        "%ASA-3-710003: UDP access denied by ACL from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-7-710005: TCP request discarded from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",        
        "%ASA-7-710005: SCTP request discarded from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-7-710006: TCP request discarded from {source_address} to {interface_name}:{dest_address}",        
        "%ASA-7-710006: ICMP request discarded from {source_address} to {interface_name}:{dest_address}",        
        "%ASA-4-733100: Bad pkts drop rate 1 exceeded. Current burst rate is 1 per second, max configured rate is 400 ; Current average rate is 760 per second, max configured rate is 100 ; Cumulative total count is 1938933",
        "%ASA-4-733100: Rate limit drop rate 1 exceeded. Current burst rate is 1 per second, max configured rate is 1 ; Current average rate is 10 per second, max configured rate is 5 ; Cumulative total count is 7867",        
        "%ASA-4-733100: ACL drop drop rate 1 exceeded. Current burst rate is 50 per second, max configured rate is 800 ; Current average rate is 3510 per second, max configured rate is 1000 ; Cumulative total count is 7687574",
        "%ASA-4-733100: Conn limit drop rate 1 exceeded. Current burst rate is 10 per second, max configured rate is 800 ; Current average rate is 2240 per second, max configured rate is 1500 ; Cumulative total count is 545132",
        "%ASA-4-733100: ICMP attack drop rate 1 exceeded. Current burst rate is 548 per second, max configured rate is 0 ; Current average rate is 1453 per second, max configured rate is 10 ; Cumulative total count is 7565876",
        "%ASA-4-733100: Scanning drop rate 1 exceeded. Current burst rate is 10 per second, max configured rate is 10 ; Current average rate is 245 per second, max configured rate is 5 ; Cumulative total count is 147409",
        "%ASA-4-733100: Inspect drop rate 1 exceeded. Current burst rate is 142 per second, max configured rate is 50 ; Current average rate is 4122 per second, max configured rate is 100 ; Cumulative total count is 453153",
        "%ASA-4-733100: Interface drop rate 1 exceeded. Current burst rate is 1 per second, max configured rate is 8000 ; Current average rate is 2040 per second, max configured rate is 2000 ; Cumulative total count is 3930654",
        "%ASA-4-733101: Subnet 10.1.0.0 is targeted. Current burst rate is 200 per second, max configured rate is 0 ; Current average rate is 425 per second, max configured rate is 0 ; Cumulative total count is 42156.",
        "%ASA-4-733101: Host {source_address} is attacking. Current burst rate is 150 per second, max configured rate is 0 ; Current average rate is 532 per second, max configured rate is 0 ; Cumulative total count is 12453.",
        "%ASA-4-733102: Threat-detection adds host {source_address} to shun list",
        "%ASA-4-733105: TD_SYSLOG_TCP_INTERCEPT_BURST_RATE_EXCEED",
        "%ASA-5-750004: Local: {local_address}:{source_port} Remote: {remote_address}:{dest_port} Username: {user} Sending COOKIE challenge to throttle possible DoS"
        ]
    anomalous_unseen = [
        "%ASA-1-106022: Deny protocol connection spoof from {source_address} to {dest_address} on interface {interface_name}.",
        "%ASA-1-106101: Number of cached deny-flows for ACL log has reached limit (100000).",
        "%ASA-1-107001: RIP auth failed from {source_address} : version=2, type=string, mode=string, sequence=number on interface {interface_name}",
        "%ASA-2-108003: Terminating SMTP connection; malicious pattern detected in the mail address from {interface_name}:{source_address}/{source_port} to {interface_name}:{dest_address}/{dest_port}.",
        "%ASA-6-201012: Per-client embryonic connection limit exceeded curr 168/100 for output packet from {source_address}/{source_port} to {dest_address}/{dest_port} on interface {interface_name}.",
        "%ASA-4-209003: Fragment database limit of number exceeded: src = {source_address} , dest = {dest_address} , proto = TCP , id = {number}",
        "%ASA-3-322002: ARP inspection check failed for arp response received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is dynamically bound to MAC Address {MAC_address}.",
        "%ASA-3-322003: ARP inspection check failed for arp request received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is not bound to any {MAC_address}",
        "%ASA-3-322003: ARP inspection check failed for arp response received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is not bound to any {MAC_address}",
        "%ASA-4-400026: IPS:3040 TCP NULL flags from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400031: IPS:4050 UDP Bomb attack from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400032: IPS:4051 UDP Snork attack from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-405001: Received ARP request collision from {source_address}/{MAC_address} on interface {interface_name} with existing ARP entry {dest_address}/{MAC_address}.",
        "%ASA-3-710003: TCP access denied by ACL from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-7-710005: UDP request discarded from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-7-710006: UDP request discarded from {source_address} to {interface_name}:{dest_address}",
        "%ASA-4-733100: {source_address} drop rate 1 exceeded. Current burst rate is 5 per second, max configured rate is 1 ; Current average rate is 24 per second, max configured rate is 5 ; Cumulative total count is 245863",
        "%ASA-4-733100: DoS attack drop rate 1 exceeded. Current burst rate is 1 per second, max configured rate is 0 ; Current average rate is 10 per second, max configured rate is 0 ; Cumulative total count is 37351",
        "%ASA-4-733100: SYN attack drop rate 1 exceeded. Current burst rate is 425 per second, max configured rate is 0 ; Current average rate is 7532 per second, max configured rate is 0 ; Cumulative total count is 45783364",
        "%ASA-4-733104: TD_SYSLOG_TCP_INTERCEPT_AVERAGE_RATE_EXCEED"
        ]
    informational_messages = [
        "%ASA-1-101001: (Primary) Failover cable OK.",		
        "%ASA-1-104500: (Primary) Switching to ACTIVE (cause: reason)",
        "%ASA-1-104500: (Secondary) Switching to ACTIVE (cause: reason)",
        "%ASA-1-104502: (Primary) Becoming Backup unit failed.",        
        "%ASA-1-105003: (Primary) Monitoring on interface {interface_name} waiting",        
        "%ASA-6-109001: Auth start for user {user} from {local_address}/{source_port} to {remote_address}/{dest_port}",
        "%ASA-6-109005: Authentication succeeded for user {user} from {local_address}/{source_port} to {remote_address}/{dest_port} on interface {interface_name}.",        
        "%ASA-3-212003: Unable to receive an SNMP request on interface {interface_name} , error code = Not responding , will try again.",        
        "%ASA-6-302003: Built H245 connection for foreign_address {remote_address}/{dest_port} local_address {local_address} /{source_port}",
        "%ASA-6-302033: Pre-allocated H323 GUP Connection for faddr {interface_name}: {remote_address}/{dest_port} to laddr {interface_name}: {local_address}/{source_port}",
        "%ASA-6-303002: FTP connection from {interface_name}:{source_address}/{source_port} to {interface_name}: {dest_address}/{dest_port} , user {user} action file filename",
        "%ASA-3-304003: URL Server {source_address} timed out URL {url}",        
        "%ASA-6-314004: RTSP client {interface_name}: {source_address} accessed RTSP URL {url}",
        "%ASA-3-318107: OSPF is enabled on {interface_name} during idb initialization",        
        "%ASA-3-318109: OSPFv3 has received an unexpected message",
        "%ASA-3-319001: Acknowledge for arp update for IP address {dest_address} not received.",
        "%ASA-3-319002: Acknowledge for route update for IP address {dest_address} not received.",
        "%ASA-4-400000: IPS:1000 IP options-Bad Option List from {source_address} to {dest_address} on interface {interface_name}",        
        "%ASA-4-400004: IPS:1004 IP options-Loose Source Route {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400005: IPS:1005 IP options-SATNET ID {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400006: IPS:1006 IP options-Strict Source Route {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400010: IPS:2000 ICMP Echo Reply {source_address} to {dest_address} on interface {interface_name}",        
        "%ASA-4-400012: IPS:2002 ICMP Source Quench {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400013: IPS:2003 ICMP Redirect {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400014: IPS:2004 ICMP Echo Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400015: IPS:2005 ICMP Time Exceeded for a Datagram {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400016: IPS:2006 ICMP Parameter Problem on Datagram {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400017: IPS:2007 ICMP Timestamp Request {source_address} to {dest_address} on interface {interface_name}",     
        "%ASA-4-400020: IPS:2010 ICMP Information Reply {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400021: IPS:2011 ICMP Address Mask Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400022: IPS:2012 ICMP Address Mask Reply {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400034: IPS:6050 DNS HINFO Request {source_address} to {dest_address} on interface {interface_name}",      
        "%ASA-4-400036: IPS:6052 DNS Zone Transfer from High Port {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400037: IPS:6053 DNS Request for All Records {source_address} to {dest_address} on interface {interface_name}",        
        "%ASA-4-400039: IPS:6101 RPC Port Unregistration {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400040: IPS:6102 RPC Dump {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400042: IPS:6150 ypserv (YP server daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",       
        "%ASA-4-400045: IPS:6153 ypupdated (YP update daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400046: IPS:6154 ypxfrd (YP transfer daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400047: IPS:6155 mountd (mount daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",        
        "%ASA-4-400049: IPS:6180 rexd (remote execution daemon) Attempt {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-401001: Shuns cleared",
        "%ASA-4-411001: Line protocol on interface {interface_name} changed state to up",
        "%ASA-4-411004: Configuration status on interface {interface_name} changed state to up",
        "%ASA-5-502111: New group policy added: name: acl_int Type: internal",        
        "%ASA-5-507001: Terminating TCP-Proxy connection from {interface_name}:{source_address}/{source_port} to {interface_name}:{dest_address}/{dest_port} - reassembly limit of 156000 bytes exceeded",
        "%ASA-4-507002: Data copy in proxy-mode exceeded the buffer limit",
        "%ASA-6-605005: Login permitted from {source_address}/{source_port} to {interface_name}:{dest_address}/{service} for user {user}",
        "%ASA-6-611101: User authentication succeeded: IP, {source_address} : Uname: {user}",
        "%ASA-5-611103: User logged out: Uname: {user}",       
        "%ASA-7-710002: UDP access permitted from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-7-713052: User {user} authenticated.",
        "%ASA-5-713155: DNS lookup for Primary VPN Server vpn_concentrator successfully resolved after a previous failure. Resetting any Backup Server init.",
        "%ASA-7-713164: The Firewall Server has requested a list of active user sessions",
        "%ASA-7-715041: Received keep-alive of type keepalive_type , not the negotiated type",
        "%ASA-4-716022: Unable to connect to proxy server.",
        "%ASA-5-718010: Sent HELLO response to {source_address}",        
        "%ASA-5-718016: Received HELLO response from {source_address}",        
        "%ASA-7-718021: Sent KEEPALIVE response to {source_address}",        
        "%ASA-7-718023: Received KEEPALIVE response from {source_address}"
        ]
    informational_unseen = [
        "%ASA-1-101002: (Primary) Bad failover cable.",
        "%ASA-1-103002: (Primary) Other firewall network interface {interface_name} OK."
        "%ASA-1-104004: (Primary) Switching to OK.",
        "%ASA-1-104502: (Secondary) Becoming Backup unit failed.",
        "%ASA-1-105004: (Primary) Monitoring on interface {interface_name} normal",
        "%ASA-6-109007: Authorization permitted for user {user} from {local_address}/{source_port} to {remote_address}/{dest_port} on interface {interface_name}.",
        "%ASA-3-212004: Unable to send an SNMP response to IP Address {source_address} Port {source_port} interface {interface_name} , error code = Unavailable",
        "%ASA-6-304004: URL Server {source_address} request failed URL {url}",
        "%ASA-3-318108: OSPF process d is changing router-id. Reconfigure virtual link neighbors with our new router-id",
        "%ASA-4-400001: IPS:1001 IP options-Record Packet Route {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400002: IPS:1002 IP options-Timestamp {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400003: IPS:1003 IP options-Security {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400011: IPS:2001 ICMP Host Unreachable {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400018: IPS:2008 ICMP Timestamp Reply {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400019: IPS:2009 ICMP Information Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400035: IPS:6051 DNS Zone Transfer {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400038: IPS:6100 RPC Port Registration {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400043: IPS:6151 ypbind (YP bind daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400044: IPS:6152 yppasswdd (YP password daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400048: IPS:6175 rexd (remote execution daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-5-502111: New group policy added: name: acl_ex Type: external",
        "%ASA-7-710002: TCP access permitted from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-5-718012: Sent HELLO request to {source_address}",
        "%ASA-5-718015: Received HELLO request from {source_address}",
        "%ASA-7-718019: Sent KEEPALIVE request to {source_address}",
        "%ASA-7-718022: Received KEEPALIVE request from {source_address}"
        ]

def generate_ip_address():
    ip_addr = Faker().ipv4()
    return ip_addr

def generate_interface_name():
    return f"GigabitEthernet0/{random.randint(0, 5)}"

def generate_port():
    return random.randint(1, 65535)

def generate_user():
    return f"user{random.randint(1, 20)}"

def generate_url():
    return Faker().url()

def generate_local_address():
    return Faker().ipv4(private=True)

def generate_remote_address():
    return Faker().ipv4(private=False)

def generate_mac_address():
    return Faker().mac_address()

def generate_number():
    return random.randint(1, 9999)

def generate_service():
    return random.choice(("DNS", "SMTP", "DHCP", "NTP"))

def pick_message():
    x = random.randint(1, 20)
    if x == 1:
        return random.choice(logTemplates.anomalous_messages), True
    else:
        return random.choice(logTemplates.informational_messages), False
    
def pick_unseen_message():
    x = random.randint(1, 20)
    if x == 1:
        return random.choice(logTemplates.anomalous_unseen), True
    else:
        return random.choice(logTemplates.informational_unseen), False
    
def fill_message(message):
    generators = {"source_address": generate_ip_address,
                      "dest_address": generate_ip_address,
                      "interface_name": generate_interface_name,
                      "source_port": generate_port,
                      "dest_port": generate_port,
                      "local_address": generate_local_address,
                      "remote_address": generate_remote_address,
                      "user": generate_user,
                      "url": generate_url,
                      "mac_address": generate_mac_address,
                      "number": generate_number,
                      "service": generate_service}
    
    parts = message.split("{")
    result = ""
    for part in parts:
        if "}" in part:
            value_type, rest = part.split("}")
            value = generators[value_type.lower()]()
            result += str(value) + rest
        else:
            result += part
    return result

def generate_log(add_label, gen_unseen):
    now = datetime.datetime.now().strftime("%b %d %Y %H:%M:%S")
    if add_label:
        if gen_unseen: # add_label == True and gen_unseen == True
            message, is_anomaly = pick_unseen_message()            
        else: # add_label == True and gen_unseen == False
            message, is_anomaly = pick_message()
        filled_message = fill_message(message)
        filled_message = f"{filled_message}\t{int(is_anomaly)}"

    else: # add_label == False
        if gen_unseen: # add_label == False and gen_unseen == True
            message, is_anomaly = pick_unseen_message()  
        else: # add_label == False and gen_unseen == False
            message, is_anomaly = pick_message()
        filled_message = fill_message(message)
    
    device = f"FW{str(random.randint(0, 25)).zfill(2)}" # generate device name
    log = f"{now} {device} : {filled_message}" # compose syslog message
    return log

def generate_logs_file(log_count, add_label, gen_unseen, filename):
    with open(filename, "w") as logs_file:
        for i in range(log_count):
 #           print(f"Generating log number {i}") # TODO: Remove before publishing
            log = f"{generate_log(add_label, gen_unseen)}\n"
            logs_file.writelines((log))
          
parser = argparse.ArgumentParser(prog="syslog_generator.py")
parser.add_argument("--number", dest="number", type=int, required=False, default=100)
parser.add_argument("--labelled", dest="labelled", choices=["yes", "no"], required=False, default="yes")
parser.add_argument("--unseen", dest="unseen", choices=["yes", "no"], required=False, default="no")

args = parser.parse_args()

generate_logs_file(args.number, args.labelled, args.unseen, "logs.txt")
    
