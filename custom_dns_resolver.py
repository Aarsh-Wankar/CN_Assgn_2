import scapy as sp
# import pandas as pd
import socket
from scapy.all import DNS, raw, DNSRR, DNSQR
import time

class Resolver:
    def __init__(self, root_server):
        self.root_server = root_server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(5)
        self.socket.bind(('10.0.0.5', 0))
            
    def resolve(self, dns_packet, depth=0):
        if depth > 10:
            return None
        if isinstance(dns_packet, bytes):
            dns_packet = DNS(dns_packet)
        start_time = time.time()
        ip_address = self.root_server
        
        while True:
            response = self.query(dns_packet, ip_address)

            if response is None:
                return None

            if response.ancount:
                for x in response.an:
                    if x.type == 1:
                        print("Resolved IP", x.rdata)
                        print("time to resolve and ip", time.time() - start_time, x.rdata)
                        return response.an[0].rdata
                    elif x.type == 5: # we get a CNAME RR back
                        dns_packet = DNS(qd = DNSQR(qname=x.rdata))
                        ip_address = self.root_server

            elif response.nscount > 0:
                this_round_done = False
                
                if response.ns[0].type == 2:
                    if response.arcount: #if the server also returns the IP address of the nameserver
                        ip_addresses = self.get_all_ipv4(response)
                        if not ip_addresses:
                            return None
                        for ip_address in ip_addresses:
                            next_response = self.query(dns_packet, ip_address)
                            if next_response:
                                response = next_response
                                this_round_done = True
                                break

                    if this_round_done: #if we already finished this round, continue
                        continue
                        
                    for i in range(response.nscount):
                        ip_address = self.resolve(DNS(qd = DNSQR(qname=response.ns[i].rdata)), depth + 1) # resolve ip of name server first
                        if ip_address:
                            break
                    else:
                        return None
                else:
                    return None
            else:
                return None #nothing to follow :(
                
    def get_all_ipv4(self, response):
        ipv4_addresses = []
        for i in range(response.arcount):
            ar = response.ar[i]
            if ar.type == 1:
                ipv4_addresses.append(ar.rdata)
        return ipv4_addresses
                
    def query(self, query_dns_packet, ip_address):
        try:
            self.socket.sendto(raw(query_dns_packet), (str(ip_address), 53))
            response_data, _ = self.socket.recvfrom(4096)
            return DNS(response_data)
        except:
            return None
            
    def listen(self):
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # listen_socket = self.socket        
        # listen_socket.bind(('127.0.0.1', 5353))
        listen_socket.bind(('10.0.0.5', 53))

        while True:
            try:
                dns_packet, client_address = listen_socket.recvfrom(512) # 512 buffer size should be big enough
            except:
                continue
            result = self.resolve(dns_packet)
            if result:
                # response = DNS(dns_packet)
                # response.an = DNSRR(rrname=response.qd.qname, rdata=result)
                # response.qr = 1
                # print(client_address)
                # listen_socket.sendto(raw(response), client_address)
                req = DNS(dns_packet)
                resp = DNS(
                    id=req.id,
                    qr=1, aa=1, ra=1, rcode=0,
                    qd=req.qd,
                    an=DNSRR(rrname=req.qd.qname, type='A', ttl=60, rdata=result)
                )
                listen_socket.sendto(raw(resp), client_address)
                print(f"Sent reply {result} to {client_address}")

if __name__ == "__main__":
    r = Resolver("198.41.0.4")
    r.listen()