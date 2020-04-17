"""
Cisco ASA Syslogs Generator for Anomaly Detection

@author: Miroslav Siklosi
"""
import time
import datetime
import sys
from faker import Faker

'''
Mar 31 2020 01:15:47 ASAX-RDS-FWHA01 : %ASA-4-419002: Duplicate TCP SYN from 
Outside:156.154.76.154/35776 to Outside:BBMWPUAG51-Ext/443 with different initial sequence number
'''

class logTemplates:
    anomalous_messages = [
        "%ASA-2-106017: Deny IP due to Land Attack from {source_address} to {dest_address}.",
        "%ASA-1-106021: Deny protocol reverse path check from {source_address} to {dest_address} on interface {interface_name}.",
        "%ASA-1-106022: Deny protocol connection spoof from {source_address} to {dest_address} on interface {interface_name}.",
        "%ASA-1-106101: Number of cached deny-flows for ACL log has reached limit ({number}).",
        "%ASA-1-107001: RIP auth failed from {source_address} : version={number}, type=string, mode=string, sequence=number on interface {interface_name}",
        "%ASA-1-107002: RIP pkt failed from {source_address} : version=number on interface {interface_name}",
        "%ASA-2-108003: Terminating SMTP connection; malicious pattern detected in the mail address from {source_interface}:{source_address}/{source_port} to {dest_interface}:{dest_address}/{dset_port}.",
        "%ASA-2-108003: Terminating ESMTP connection; malicious pattern detected in the mail address from {source_interface}:{source_address}/{source_port} to {dest_interface}:{dest_address}/{dset_port}.",
        "%ASA-4-109017: User at {source_address} exceeded auth proxy connection limit ({max}).",
        "%ASA-2-201003: Embryonic limit exceeded nconns/elimit for {outside_address}/{dest_port} (global_address ) {local_address}/{{source_port}} on interface {interface_name}.",
        "%ASA-6-201012: Per-client embryonic connection limit exceeded curr num /limit for input packet from {source_address}/{source_port} to {dest_address}/{dest_port} on interface {interface_name}.",
        "%ASA-6-201012: Per-client embryonic connection limit exceeded curr num /limit for output packet from {source_address}/{source_port} to {dest_address}/{dest_port} on interface {interface_name}.",
        "%ASA-4-209003: Fragment database limit of number exceeded: src = {source_address} , dest = {dest_address} , proto = {protocol} , id = {number}",
        "%ASA-3-322001: Deny MAC address {MAC_address}, possible spoof attempt on interface {interface_name}",
        "%ASA-3-322002: ARP inspection check failed for arp request received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is statically bound to MAC Address {MAC_address}.",
        "%ASA-3-322002: ARP inspection check failed for arp request received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is dynamically bound to MAC Address {MAC_address}.",
        "%ASA-3-322002: ARP inspection check failed for arp response received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is statically bound to MAC Address {MAC_address}.",
        "%ASA-3-322002: ARP inspection check failed for arp response received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is dynamically bound to MAC Address {MAC_address}.",
        "%ASA-3-322003: ARP inspection check failed for arp request received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is not bound to any {MAC Address}",
        "%ASA-3-322003: ARP inspection check failed for arp response received from host {MAC_address} on interface {interface_name}. This host is advertising MAC Address {MAC_address} for IP Address {source_address}, which is not bound to any {MAC Address}",
        "%ASA-4-400007: IPS:1100 IP Fragment Attack from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400008: IPS:1102 IP Impossible Packet from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400009: IPS:1103 IP Fragments Overlap from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400023: IPS:2150 Fragmented ICMP Traffic from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400024: IPS:2151 Large ICMP Traffic from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400025: IPS:2154 Ping of Death Attack from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400026: IPS:3040 TCP NULL flags from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400027: IPS:3041 TCP SYN+FIN flags from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400028: IPS:3042 TCP FIN only flags from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400029: IPS:3153 FTP Improper Address Specified from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400030: IPS:3154 FTP Improper Port Specified from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400031: IPS:4050 UDP Bomb attack from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400032: IPS:4051 UDP Snork attack from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400033: IPS:4052 UDP Chargen DoS attack from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400041: IPS:6103 Proxied RPC Request from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400050: IPS:6190 statd Buffer Overflow from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-5-402128: CRYPTO: An attempt to allocate a large memory block failed, size: {size} , limit: {limit}",
        "%ASA-4-405001: Received ARP request collision from {source_address}/{MAC_address} on interface {interface_name} with existing ARP entry {dest_address}/{MAC_address}.",
        "%ASA-4-405001: Received ARP response collision from {source_address}/{MAC_address} on interface {interface_name} with existing ARP entry {dest_address}/{MAC_address}.",
        "%ASA-4-405002: Received mac mismatch collision from {source_address} /{MAC_address} for authenticated host",
        "%ASA-2-410002: Dropped num DNS responses with mis-matched id in the past sec second(s): from {interface_name}:{source_address}/{source_port} to {interface_name}:{dest_address}/{dest_port}",
        "%ASA-4-419002: Received duplicate TCP SYN from {interface_name}:{src_address}/{source_port} to {interface_name}:{dest_address}/{dest_port} with different initial sequence number.",
        "%ASA-6-605004: Login denied from {source_address}/{source_port} to {interface_name}:{dest_address}/{service} for user {user}",
        "%ASA-3-710003: TCP access denied by ACL from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-3-710003: UDP access denied by ACL from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-7-710005: TCP request discarded from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-7-710005: UDP request discarded from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-7-710005: SCTP request discarded from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-7-710006: protocol request discarded from {source_address} to {interface_name}:{dest_address}",
        "%ASA-4-733100: Object drop rate rate_ID exceeded. Current burst rate is rate_val per second, max configured rate is rate_val ; Current average rate is rate_val per second, max configured rate is rate_val ; Cumulative total count is total_cnt",
        "%ASA-4-733101: Object {source_address} (is targeted|is attacking). Current burst rate is rate_val per second, max configured rate is rate_val ; Current average rate is rate_val per second, max configured rate is rate_val ; Cumulative total count is total_cnt.",
        "%ASA-4-733102: Threat-detection adds host %I to shun list",
        "%ASA-4-733104: TD_SYSLOG_TCP_INTERCEPT_AVERAGE_RATE_EXCEED",
        "%ASA-4-733105: TD_SYSLOG_TCP_INTERCEPT_BURST_RATE_EXCEED",
        "%ASA-5-750004: Local: {local_address}: {source_port} Remote: {remote_address}: {dest_port} Username: {user} Sending COOKIE challenge to throttle possible DoS"
        ]
    informational_messages = [
        "%ASA-1-101001: (Primary) Failover cable OK.",
        "%ASA-1-101002: (Primary) Bad failover cable.",
        "%ASA-1-103002: (Primary) Other firewall network interface interface_number OK.",
        "%ASA-1-104004: (Primary) Switching to OK.",
        "%ASA-1-104500: (Primary) Switching to ACTIVE (cause: reason)",
        "%ASA-1-104500: (Secondary) Switching to ACTIVE (cause: reason)",
        "%ASA-1-104502: (Primary) Becoming Backup unit failed.",
        "%ASA-1-104502: (Secondary) Becoming Backup unit failed.",
        "%ASA-1-105003: (Primary) Monitoring on interface {interface_name} waiting",
        "%ASA-1-105004: (Primary) Monitoring on interface {interface_name} normal",
        "%ASA-6-109001: Auth start for user {user} from {local_address}/{source_port} to {remote_address}/{dest_port}",
        "%ASA-6-109005: Authentication succeeded for user user from {local_address}/{source_port} to outside_address/{dest_port} on interface {interface_name}.",
        "%ASA-6-109007: Authorization permitted for user user from {local_address}/{source_port} to outside_address/{dest_port} on interface {interface_name}.",
        "%ASA-3-212003: Unable to receive an SNMP request on interface interface_number , error code = code , will try again.",
        "%ASA-3-212004: Unable to send an SNMP response to IP Address {source_address} Port port interface interface_number , error code = code",
        "%ASA-6-302003: Built H245 connection for foreign_address outside_address /{dest_port} local_address {local_address} /{source_port}",
        "%ASA-6-302033: Pre-allocated H323 GUP Connection for faddr interface :foreign address /foreign-port to laddr interface :local-address /local-port",
        "%ASA-6-303002: FTP connection from src_ifc :src_ip /{source_port} to dst_ifc :dst_ip /dst_port , user username action file filename",
        "%ASA-5-303005: Strict FTP inspection matched match_string in policy-map policy-name , action_string from src_ifc :sip /sport to dest_ifc :dip /dport",
        "%ASA-3-304003: URL Server {source_address} timed out URL url",
        "%ASA-6-304004: URL Server {source_address} request failed URL url",
        "%ASA-6-314004: RTSP client src_intf:src_IP accessed RTSP URL RTSP URL",
        "%ASA-3-318107: OSPF is enabled on IF_NAME during idb initialization",
        "%ASA-3-318108: OSPF process d is changing router-id. Reconfigure virtual link neighbors with our new router-id",
        "%ASA-3-318109: OSPFv3 has received an unexpected message",
        "%ASA-3-319001: Acknowledge for arp update for IP address {dest_address} not received (number ).",
        "%ASA-3-319002: Acknowledge for route update for IP address {dest_address} not received (number ).",
        "%ASA-4-400000: IPS:1000 IP options-Bad Option List from {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400001: IPS:1001 IP options-Record Packet Route {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400002: IPS:1002 IP options-Timestamp {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400003: IPS:1003 IP options-Security {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400004: IPS:1004 IP options-Loose Source Route {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400005: IPS:1005 IP options-SATNET ID {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400006: IPS:1006 IP options-Strict Source Route {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400010: IPS:2000 ICMP Echo Reply {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400011: IPS:2001 ICMP Host Unreachable {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400012: IPS:2002 ICMP Source Quench {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400013: IPS:2003 ICMP Redirect {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400014: IPS:2004 ICMP Echo Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400015: IPS:2005 ICMP Time Exceeded for a Datagram {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400016: IPS:2006 ICMP Parameter Problem on Datagram {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400017: IPS:2007 ICMP Timestamp Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400018: IPS:2008 ICMP Timestamp Reply {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400019: IPS:2009 ICMP Information Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400020: IPS:2010 ICMP Information Reply {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400021: IPS:2011 ICMP Address Mask Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400022: IPS:2012 ICMP Address Mask Reply {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400034: IPS:6050 DNS HINFO Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400035: IPS:6051 DNS Zone Transfer {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400036: IPS:6052 DNS Zone Transfer from High Port {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400037: IPS:6053 DNS Request for All Records {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400038: IPS:6100 RPC Port Registration {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400039: IPS:6101 RPC Port Unregistration {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400040: IPS:6102 RPC Dump {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400042: IPS:6150 ypserv (YP server daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400043: IPS:6151 ypbind (YP bind daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400044: IPS:6152 yppasswdd (YP password daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400045: IPS:6153 ypupdated (YP update daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400046: IPS:6154 ypxfrd (YP transfer daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400047: IPS:6155 mountd (mount daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400048: IPS:6175 rexd (remote execution daemon) Portmap Request {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-400049: IPS:6180 rexd (remote execution daemon) Attempt {source_address} to {dest_address} on interface {interface_name}",
        "%ASA-4-401001: Shuns cleared",
        "%ASA-4-408002: ospf process id route type update address1 netmask1 [distance1/metric1 ] via source IP :interface1 address2 netmask2 [distance2 /metric2 ] interface2",
        "%ASA-4-411001: Line protocol on interface {interface_name} changed state to up",
        "%ASA-4-411004: Configuration status on interface {interface_name} changed state to up",
        "%ASA-5-502111: New group policy added: name: policy_name Type: policy_type",
        "%ASA-5-507001: Terminating TCP-Proxy connection from {interface_name}:{source_address}/{source_port} to {interface_name}:{dest_address}/{dest_port} - reassembly limit of limit bytes exceeded",
        "%ASA-4-507002: Data copy in proxy-mode exceeded the buffer limit",
        "%ASA-6-605005: Login permitted from {source_address}/{source_port} to {interface_name}:{dest_address}/{service} for user {user}",
        "%ASA-6-611101: User authentication succeeded: IP, IP address : Uname: {user}",
        "%ASA-5-611103: User logged out: Uname: {user}",
        "%ASA-7-710002: TCP access permitted from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-7-710002: UDP access permitted from {source_address}/{source_port} to {interface_name}:{dest_address}/{service}",
        "%ASA-7-713052: User {user} authenticated.",
        "%ASA-5-713155: DNS lookup for Primary VPN Server [server_name ] successfully resolved after a previous failure. Resetting any Backup Server init.",
        "%ASA-7-713164: The Firewall Server has requested a list of active user sessions",
        "%ASA-7-715041: Received keep-alive of type keepalive_type , not the negotiated type",
        "%ASA-4-716022: Unable to connect to proxy server.",
        "%ASA-5-718010: Sent HELLO response to {source_address}",
        "%ASA-5-718012: Sent HELLO request to {source_address}",
        "%ASA-5-718015: Received HELLO request from {source_address}",
        "%ASA-5-718016: Received HELLO response from {source_address}",
        "%ASA-7-718019: Sent KEEPALIVE request to {source_address}",
        "%ASA-7-718021: Sent KEEPALIVE response to {source_address}",
        "%ASA-7-718022: Received KEEPALIVE request from {source_address}",
        "%ASA-7-718023: Received KEEPALIVE response from {source_address}",
        ]
   
def get_messages(log_type: LogType): 
    if not isinstance(log_type, LogType): 
        sys \ 
            .exit("Used wrong type of logs. Used: {}. You can use: {}. Additional info: please, use enum LogType." 
                  .format(log_type, LogType.get_all_names())) 
 
    if log_type == LogType.anomalous: 
        return logTemplates.anomalous_messages 
    elif log_type == LogType.informational: 
        return logTemplates.informational_messages
    
def get_percentage_message(self, percentage: int, log_type: LogType): 
	message_templates = self.get_messages(log_type) 
	message = random.choice(message_templates) 
	try: 
		return message.format(percentage) 
	# generating log without information about usage 
	except IndexError: 
		return message
    
faker = Faker()  
ip_addr = faker.ipv4() 


def generate_logs(self, param_count_of_logs: int): 
        """ 
        :return:  
        """ 
        logs: list = [] 
        for number in range(param_count_of_logs): 
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # TODO: adjust datetime
            device = random.choice()
            logs.append(Log(now, self.get_percentage_message(random.randint(20, 100), LogType.anomalous), "Device" + str(number + 1))) 
            logs.append(Log(now, self.get_percentage_message(random.randint(20, 100), LogType.informational), "Device" + str(number + 1))) 
        return logs 
    
    
    
    
    