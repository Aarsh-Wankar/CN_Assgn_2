import socket
import time
import datetime
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE, RCODE
from dnslib.server import DNSServer, BaseResolver

# --- Configuration ---
# IP of a.root-servers.net. This is our starting point.
ROOT_SERVER_IP = "198.41.0.4" 
# The IP of our resolver in Mininet
LISTEN_IP = "10.0.0.5"
LOG_FILE = "dns_resolver.log"

class IterativeResolver(BaseResolver):
    """
    An iterative DNS resolver that implements the logic for
    Parts D and F (Caching) of the assignment.
    """
    
    def __init__(self):
        # Our cache will store: {qname: (timestamp, ttl, [answers])}
        self.cache = {}
        self.log_file = open(LOG_FILE, "w", buffering=1) # Line-buffered
        self.log(f"--- Iterative DNS Resolver starting on {LISTEN_IP} ---")

    def log(self, *args):
        """
        Helper function to log all required items to console and a file.
        This function directly helps with Part D logging requirements.
        """
        timestamp = datetime.datetime.now().isoformat() # (a) Timestamp
        log_message = f"{timestamp} - {' '.join(str(a) for a in args)}\n"
        print(log_message, end="") # Print to console
        self.log_file.write(log_message)

    def resolve(self, request, handler):
        """
        This is the main function called by DNSServer for every incoming query.
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype

        # (b) Domain name queried
        self.log(f"[QUERY] Received query for: {qname} (Type: {QTYPE[qtype]})")
        
        # (c) Resolution mode
        # We check the RD (Recursion Desired) flag.
        # For this assignment, we'll always perform iterative (recursive)
        # resolution if the client asks for it.
        if request.header.rd:
            self.log("[MODE] Recursive (Client requested, we will iterate)")
        else:
            self.log("[MODE] Iterative (Client did not request recursion)")
            # In a real server, we might respond differently.
            # For this assignment, we'll proceed anyway.

        # --- (i) Cache status (Bonus F) ---
        if qname in self.cache:
            timestamp, ttl, answers = self.cache[qname]
            if (time.time() - timestamp) < ttl:
                self.log(f"[CACHE] {qname}", "HIT") # (i) Cache Status
                for answer in answers:
                    reply.add_answer(answer)
                return reply
            else:
                self.log(f"[CACHE] {qname}", "EXPIRED")
                del self.cache[qname]
        
        self.log(f"[CACHE] {qname}", "MISS") # (i) Cache Status

        # --- Start Iterative Resolution ---
        total_start_time = time.time()
        
        # Start our search at the root servers
        next_server_ip = ROOT_SERVER
        
        try:
            # We will iterate 3 times: Root -> TLD -> Authoritative
            for step in ["Root", "TLD", "Authoritative"]:
                
                # (e) Step of resolution
                self.log(f"[STEP] {step}: Querying server {next_server_ip} for {qname}")
                
                # Send the query to the current server
                # (d) DNS server IP contacted
                response, rtt = self.send_query(request, next_server_ip)
                
                # (g) Round-trip time to that server
                self.log(f"[RECV] Received response from {next_server_ip}. RTT: {rtt:.2f} ms")
                # (f) Response or referral received (we log details below)
                
                if not response:
                    self.log("[ERROR] No response from server. Failing.")
                    reply.header.rcode = RCODE.SERVFAIL
                    break

                # --- Decision Logic ---
                if response.header.rcode == RCODE.NOERROR:
                    if response.rr:
                        # --- SUCCESS ---
                        # We got an answer! (A, AAAA, or CNAME)
                        self.log(f"[SUCCESS] Found final answer(s) for {qname}")
                        reply.add_answer(*response.rr) # Add all answers to our reply
                        
                        # --- Store in Cache (Bonus F) ---
                        # Use the TTL from the first answer record
                        ttl = response.rr[0].ttl
                        self.cache[qname] = (time.time(), ttl, response.rr)
                        self.log(f"[CACHE] Storing {qname} in cache. TTL: {ttl}s")
                        
                        break # We are done

                    elif response.auth:
                        # --- REFERRAL ---
                        # No answer, but we got an Authority (referral)
                        self.log(f"[REFERRAL] Got referral from {next_server_ip}")
                        
                        # Find the IP of the *next* server (glue record)
                        next_server_ip = self.find_glue_record(response)
                        
                        if next_server_ip:
                            self.log(f"[REFERRAL] Next server to query: {next_server_ip}")
                            continue # Continue to the next loop iteration
                        else:
                            self.log("[ERROR] No glue record found in referral. Failing.")
                            reply.header.rcode = RCODE.SERVFAIL
                            break
                    else:
                        # Should not happen, but good to handle
                        self.log("[ERROR] No answer and no referral. Failing.")
                        reply.header.rcode = RCODE.SERVFAIL
                        break
                
                elif response.header.rcode == RCODE.NXDOMAIN:
                    # The domain does not exist
                    self.log(f"[NXDOMAIN] Server reports {qname} does not exist.")
                    reply.header.rcode = RCODE.NXDOMAIN
                    break
                else:
                    # Any other error
                    self.log(f"[ERROR] Upstream server returned error: {RCODE[response.header.rcode]}")
                    reply.header.rcode = response.header.rcode
                    break
            else:
                # This 'else' triggers if the 'for' loop finishes without 'break'
                self.log("[ERROR] Iteration limit (3 steps) reached without answer. Failing.")
                reply.header.rcode = RCODE.SERVFAIL

        except Exception as e:
            self.log(f"[FATAL] Unhandled exception: {e}")
            reply.header.rcode = RCODE.SERVFAIL
        
        total_end_time = time.time()
        total_time_ms = (total_end_time - total_start_time) * 1000
        
        # (h) Total time to resolution
        self.log(f"[DONE] Total resolution time: {total_time_ms:.2f} ms")
        
        return reply

    def send_query(self, request, server_ip):
        """
        Sends a DNS query to a specific server and measures RTT.
        """
        try:
            # Create a new query packet from the original request
            query_msg = request.pack()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0) # 2 second timeout
            
            rtt_start = time.time()
            sock.sendto(query_msg, (server_ip, 53))
            response_bytes, _ = sock.recvfrom(2048)
            rtt_end = time.time()
            
            rtt_ms = (rtt_end - rtt_start) * 1000
            
            return DNSRecord.parse(response_bytes), rtt_ms
            
        except socket.timeout:
            self.log(f"[TIMEOUT] Query to {server_ip} timed out.")
            return None, 0
        except Exception as e:
            self.log(f"[ERROR] Failed to send query to {server_ip}: {e}")
            return None, 0

    def find_glue_record(self, response):
        """
        Finds the IP address (A record) from the 'Additional' section
        that matches a Nameserver (NS) in the 'Authority' section.
        """
        # Get all nameserver names from the Authority section
        ns_names = [str(r.rdata.label) for r in response.auth if r.rtype == QTYPE.NS]
        if not ns_names:
            return None
        
        # Find the first 'A' record in the Additional section
        # that matches one of the nameserver names
        for glue_record in response.ar:
            if glue_record.rtype == QTYPE.A and str(glue_record.rname) in ns_names:
                self.log(f"[GLUE] Found glue record: {glue_record.rname} -> {glue_record.rdata}")
                return str(glue_record.rdata)
        
        # No glue record found.
        # A real resolver would now have to resolve the NS name itself.
        # For this assignment, we'll stop here.
        return None

# --- Main server execution ---
if __name__ == "__main__":
    try:
        resolver = IterativeResolver()
        server = DNSServer(resolver, port=53, address=LISTEN_IP)
        server.start()
    except Exception as e:
        print(f"Failed to start server on {LISTEN_IP}: {e}")
        print("Are you running this with sudo?")
