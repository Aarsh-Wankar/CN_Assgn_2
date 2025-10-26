import scapy as sp
import socket
from scapy.all import DNS, raw, DNSRR, DNSQR
import time
from datetime import datetime
import threading

class Resolver:
    def __init__(self, root_server):
        self.root_server = root_server
        self.log_lock = threading.Lock()
        
    def log(self, log_buffer, msg, need_time=True):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        if need_time: log_line = f"[{timestamp}] {msg}"
        else: log_line = msg
        
        print(log_line) # Print immediately
        log_buffer.append(log_line) # Add to the thread's private list

            
    def resolve(self, dns_packet, log_buffer, query_count, depth=0, original_domain=None, start_time=None):
        if isinstance(dns_packet, bytes):
            dns_packet = DNS(dns_packet)
        
        level_count = [0]
        if depth == 0:
            original_domain = str(dns_packet.qd.qname.decode() if isinstance(dns_packet.qd.qname, bytes) else dns_packet.qd.qname)
            start_time = time.time()
            self.log(log_buffer, f"Domain: {original_domain} | Mode: Iterative")
            
        next_server_ip = [self.root_server]
        response = None

        while True:
            step = "Root" if level_count[0] == 0 else ("TLD" if level_count[0] == 1 else "Authoritative")
            
            query_start = time.time()
            for ip in next_server_ip:
                response = self.query(dns_packet, ip, query_count)
                if response: break
            rtt = time.time() - query_start

            if response is None:
                self.log(log_buffer, f"Server: {next_server_ip} | Step: {step} | RTT: {rtt:.4f}s | Response: FAILED")
                self.log(log_buffer, f"Domain: {original_domain} | Total Time: {time.time() - start_time:.4f}s | Status: FAILED")
                return None

            if response.ancount:
                for x in response.an:
                    if x.type == 1:
                        self.log(log_buffer, f"Server: {next_server_ip} | Step: {step} | RTT: {rtt:.4f}s | Response: ANSWER | IP: {x.rdata}")
                        if depth == 0:
                            self.log(log_buffer, f"Domain: {original_domain} | Total Time: {time.time() - start_time:.4f}s | Resolved IP: {x.rdata} | Total DNS Servers visited : {query_count[0]}")
                        return response.an[0].rdata
                    elif x.type == 5:
                        self.log(log_buffer, f"Server: {next_server_ip} | Step: {step} | RTT: {rtt:.4f}s | Response: CNAME | Target: {x.rdata}")
                        dns_packet = DNS(qd = DNSQR(qname=x.rdata))
                        next_server_ip = self.root_server
                        continue 

            elif response.nscount > 0:
                if response.ns[0].type == 2:
                    self.log(log_buffer, f"Server: {next_server_ip} | Step: {step} | RTT: {rtt:.4f}s | Response: REFERRAL | NS: {response.ns[0].rdata}")
                    level_count[0] += 1
                    
                    if response.arcount: #if the IP addresses of nameservers are already present in additional section
                        ip_addresses = self.get_all_ipv4(response)
                        if not ip_addresses:
                            return None
                        
                        next_server_ip = ip_addresses
                        continue 
                        
                    resolved_ns_ip = None 
                    next_server_ip = []
                    for i in range(response.nscount):
                        ns_name = response.ns[i].rdata
                        self.log(log_buffer, f"Attempting to resolve NS: {ns_name}")
                        resolved_ns_ip = self.resolve(DNS(qd = DNSQR(qname=ns_name)), log_buffer, query_count, depth + 1, original_domain, start_time)
                        if resolved_ns_ip: next_server_ip.append(resolved_ns_ip)

                    if not next_server_ip:
                        self.log(log_buffer, f"Failed to resolve any NS records")
                        self.log(log_buffer, f"Domain: {original_domain} | Total Time: {time.time() - start_time:.4f}s | Status: FAILED (NS Resolution)")
                        return None
                else:
                    return None
            else:
                return None
                
    def get_all_ipv4(self, response):
        ipv4_addresses = []
        for i in range(response.arcount):
            ar = response.ar[i]
            if ar.type == 1:
                ipv4_addresses.append(ar.rdata)
        return ipv4_addresses
                
    def query(self, query_dns_packet, ip_address, query_count):
        # This is now thread-safe because query_count is a list
        # unique to this thread's execution.
        query_count[0] += 1 
        try:
            query_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            query_socket.settimeout(5)
            query_socket.sendto(raw(query_dns_packet), (str(ip_address), 53))
            response_data, _ = query_socket.recvfrom(4096)
            query_socket.close()
            return DNS(response_data)
        except Exception as e:
            return None
            
    def listen(self):
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_socket.bind(('10.0.0.5', 53))
        print("--- DNS Server Listening on 10.0.0.5:53 ---")

        while True:
            try:
                dns_packet_bytes, client_address = listen_socket.recvfrom(4096)
                
                client_thread = threading.Thread(
                    target=self.handle_query, 
                    args=(dns_packet_bytes, client_address, listen_socket),
                    daemon=True
                )
                client_thread.start()
                
            except Exception as e:
                print(f"Listen loop error: {e}")
                continue
    
    def handle_query(self, dns_packet_bytes, client_address, listen_socket):
        log_buffer = [] # 1. Create the private log list
        query_count = [0] # 2. Create the private query counter
        
        try:
            dns_packet = DNS(dns_packet_bytes)
            
            clean_packet = DNS(qd=DNSQR(qname=dns_packet.qd[0].qname)) 
            
            # 3. Pass the private log_buffer and query_count
            result = self.resolve(clean_packet, log_buffer, query_count)
            
            if result:
                req = DNS(dns_packet_bytes) 
                resp = DNS(
                    id=req.id,
                    qr=1, aa=0, ra=1, rcode=0, 
                    qd=req.qd,
                    an=DNSRR(rrname=req.qd.qname, type='A', ttl=60, rdata=result)
                )
                listen_socket.sendto(raw(resp), client_address)
                print(f"Sent reply {result} to {client_address}")
            
            # 4. AFTER everything, write the grouped logs to the file
            with self.log_lock:
                with open('dns_resolution.log', 'a') as f:
                    f.write("\n----- New Query -----\n")
                    f.write("\n".join(log_buffer))
                    f.write("\n----- End Query -----\n")
                    
        except Exception as e:
            print(f"Error in handle_query thread: {e}")
            with self.log_lock:
                with open('dns_resolution.log', 'a') as f:
                    f.write("\n----- Query Failed (Exception) -----\n")
                    f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] {e}\n")
                    f.write("\n".join(log_buffer))
                    f.write("\n----- End Query -----\n")


if __name__ == "__main__":
    r = Resolver("198.41.0.4")
    r.listen()

