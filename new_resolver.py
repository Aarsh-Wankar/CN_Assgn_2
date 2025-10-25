#!/usr/bin/env python3

import socket
import struct
import time
import datetime
import random
import sys

# --- Configuration ---
ROOT_SERVER_IP = "198.41.0.4" # a.root-servers.net
LISTEN_IP = "10.0.0.5"
LISTEN_PORT = 53
LOG_FILE = "dns_resolver.log"

# --- DNS Record Types ---
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_AAAA = 28

# --- Cache ---
# { qname: (timestamp, ttl, response_packet) }
CACHE = {}

# --- Logger ---
try:
    log_file = open(LOG_FILE, "w", buffering=1) # Line-buffered
except PermissionError:
    print(f"Error: Could not write to {LOG_FILE}. Check permissions.", file=sys.stderr)
    sys.exit(1)

def log(*args):
    """
    Helper function to log all required items to console and a file.
    This function directly helps with Part D logging requirements.
    """
    timestamp = datetime.datetime.now().isoformat() # (a) Timestamp
    log_message = f"{timestamp} - {' '.join(str(a) for a in args)}\n"
    print(log_message, end="") # Print to console
    log_file.write(log_message)

# ===============================================
# == DNS PACKET BUILDER
# ===============================================

def encode_qname(domain_name):
    """
    Encodes a domain name like 'www.google.com' into
    DNS format: b'\x03www\x06google\x03com\x00'
    """
    parts = domain_name.encode('ascii').split(b'.')
    encoded = b''
    for part in parts:
        encoded += bytes([len(part)]) + part
    return encoded + b'\x00'

def build_dns_query_packet(qname, qtype, query_id):
    """
    Builds a complete DNS query packet as bytes.
    """
    # Header (12 bytes)
    header = struct.pack(
        '!HHHHHH',
        query_id,  # (2 bytes) Transaction ID
        0x0100,    # (2 bytes) Flags: 0x0100 = Standard query, Recursion Desired
        1,         # (2 bytes) QDCOUNT (Number of questions)
        0,         # (2 bytes) ANCOUNT (Number of answers)
        0,         # (2 bytes) NSCOUNT (Number of authority records)
        0          # (2 bytes) ARCOUNT (Number of additional records)
    )
    
    # Question (variable length)
    question = encode_qname(qname) + struct.pack('!HH', qtype, 1) # 1 = QCLASS IN (Internet)
    
    return header + question

# ===============================================
# == DNS PACKET PARSER
# ===============================================

def parse_name(data, offset):
    """
    Parses a (potentially compressed) domain name from a DNS packet.
    Returns: (str: domain_name, int: new_offset)
    """
    name_parts = []
    original_offset = offset
    seen_pointer = False

    while True:
        length_byte = data[offset]
        
        # Check for pointer (compression)
        if (length_byte & 0xC0) == 0xC0:
            # It's a pointer!
            pointer_bytes = struct.unpack('!H', data[offset:offset+2])[0]
            pointer = pointer_bytes & 0x3FFF # Get offset from last 14 bits
            
            # Recurse to parse the name at the pointer location
            (pointed_name, _) = parse_name(data, pointer)
            name_parts.append(pointed_name)
            
            offset += 2 # Pointers are always 2 bytes
            if not seen_pointer:
                original_offset = offset
            
            seen_pointer = True
            break # A pointer is always the end of a name
            
        elif length_byte == 0x00:
            # End of name
            offset += 1
            if not seen_pointer:
                original_offset = offset
            break
        
        else:
            # It's a label length
            offset += 1
            label = data[offset:offset+length_byte].decode('ascii', errors='ignore')
            name_parts.append(label)
            offset += length_byte

    return ".".join(name_parts), original_offset

def parse_dns_packet(data):
    """
    Parses a raw DNS response packet.
    Returns a dict: {'answers': [], 'authorities': [], 'additionals': []}
    """
    try:
        # Unpack header
        header = data[:12]
        (query_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack('!HHHHHH', header)
        
        rcode = flags & 0x000F
        if rcode == 3: # NXDOMAIN
            return {'rcode': 3, 'answers': [], 'authorities': [], 'additionals': []}

        # Start parsing after the header
        offset = 12
        
        # Skip Question section
        for _ in range(qdcount):
            _, offset = parse_name(data, offset) # Skip QNAME
            offset += 4 # Skip QTYPE (2) and QCLASS (2)
            
        # Parse resource record sections
        answers = []
        for _ in range(ancount):
            rr = parse_resource_record(data, offset)
            answers.append(rr)
            offset = rr['new_offset']

        authorities = []
        for _ in range(nscount):
            rr = parse_resource_record(data, offset)
            authorities.append(rr)
            offset = rr['new_offset']
            
        additionals = []
        for _ in range(arcount):
            rr = parse_resource_record(data, offset)
            additionals.append(rr)
            offset = rr['new_offset']

        return {'rcode': rcode, 'answers': answers, 'authorities': authorities, 'additionals': additionals}

    except Exception as e:
        log(f"[PARSE_ERROR] Failed to parse packet: {e}, Data: {data[:50]}...")
        return {'rcode': 1, 'answers': [], 'authorities': [], 'additionals': []} # RCODE 1 = Format Error

def parse_resource_record(data, offset):
    """
    Helper function to parse a single RR.
    Returns a dict: {'name': str, 'type': int, 'ttl': int, 'rdata': str, 'new_offset': int}
    """
    name, offset = parse_name(data, offset)
    
    # Unpack fixed part of RR
    rr_type, rr_class, rr_ttl, rr_rdlength = struct.unpack('!HHIH', data[offset:offset+10])
    offset += 10
    
    rdata = None
    if rr_type == QTYPE_A:
        # RDATA is an IP address
        rdata = socket.inet_ntoa(data[offset:offset+rr_rdlength])
    elif rr_type == QTYPE_NS or rr_type == QTYPE_CNAME:
        # RDATA is a domain name
        (rdata, _) = parse_name(data, offset)
    else:
        # Other type, just store as bytes
        rdata = data[offset:offset+rr_rdlength].hex()

    return {
        'name': name,
        'type': rr_type,
        'ttl': rr_ttl,
        'rdata': rdata,
        'new_offset': offset + rr_rdlength
    }

# ===============================================
# == RESOLVER LOGIC
# ===============================================

def resolve_iterative(original_query_packet, qname):
    """
    Performs the iterative resolution and returns the final response packet.
    """
    total_start_time = time.time()
    next_server_ip = ROOT_SERVER_IP
    
    # We will just forward the original query packet
    # This is simpler than building a new one
    
    for step in ["Root", "TLD", "Authoritative", "Final"]:
        # (e) Step of resolution
        log(f"[STEP] {step}: Querying {next_server_ip} for {qname}")
        
        # (d) DNS server IP contacted
        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_sock.settimeout(2.0)
        
        try:
            rtt_start = time.time()
            # Send the *original client's query* to the upstream server
            upstream_sock.sendto(original_query_packet, (next_server_ip, 53))
            response_bytes, _ = upstream_sock.recvfrom(2048)
            rtt_end = time.time()
            
            # (g) Round-trip time
            rtt_ms = (rtt_end - rtt_start) * 1000
            log(f"[RECV] Received response from {next_server_ip}. RTT: {rtt_ms:.2f} ms")
            
            # (f) Response or referral received
            parsed_response = parse_dns_packet(response_bytes)

            # --- Decision Logic ---
            if parsed_response['rcode'] == 3: # NXDOMAIN
                log(f"[NXDOMAIN] Server reports {qname} does not exist.")
                return response_bytes # Return the NXDOMAIN response
                
            if parsed_response['answers']:
                # We found an answer!
                for ans in parsed_response['answers']:
                    if ans['type'] == QTYPE_A:
                        log(f"[SUCCESS] Found A record: {ans['name']} -> {ans['rdata']}")
                        
                        # (i) Cache Status (Bonus F)
                        ttl = ans['ttl']
                        CACHE[qname] = (time.time(), ttl, response_bytes)
                        log(f"[CACHE] Storing {qname} in cache. TTL: {ttl}s")
                        
                        return response_bytes # Return the full packet
                    if ans['type'] == QTYPE_CNAME:
                        log(f"[CNAME] Found CNAME: {ans['name']} -> {ans['rdata']}")
                        # A real resolver would restart resolution for the CNAME
                        # For this assignment, we'll just return the CNAME
                        return response_bytes

                log("[INFO] Answer section found, but no A or CNAME. Continuing...")

            # No answers, look for a referral in the Authority section
            glue_ip = None
            if parsed_response['authorities']:
                for auth_rr in parsed_response['authorities']:
                    if auth_rr['type'] == QTYPE_NS:
                        ns_name = auth_rr['rdata']
                        # Now look for a matching 'A' record in the Additional section
                        for add_rr in parsed_response['additionals']:
                            if add_rr['type'] == QTYPE_A and add_rr['name'] == ns_name:
                                glue_ip = add_rr['rdata']
                                log(f"[REFERRAL] Found glue record for {ns_name} -> {glue_ip}")
                                break
                    if glue_ip:
                        break

            if glue_ip:
                next_server_ip = glue_ip
                continue # Go to the next iteration of the loop
            else:
                log("[ERROR] No answers and no usable glue records found. Failing.")
                return None # Failed to resolve
                
        except socket.timeout:
            log(f"[TIMEOUT] Query to {next_server_ip} timed out.")
            return None # Failed to resolve
        except Exception as e:
            log(f"[ERROR] Unhandled exception during query: {e}")
            return None # Failed to resolve
        finally:
            upstream_sock.close()
            
    log("[ERROR] Iteration limit reached without answer. Failing.")
    return None

# ===============================================
# == MAIN SERVER LOOP
# ===============================================

def main():
    log(f"--- DNS Resolver starting on {LISTEN_IP}:{LISTEN_PORT} (from scratch) ---")
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((LISTEN_IP, LISTEN_PORT))
    
    while True:
        try:
            # 1. Receive query from client
            query_packet, client_addr = server_sock.recvfrom(512)
            
            # Get original transaction ID and QNAME
            original_txid = query_packet[:2]
            # Parse qname (this is crude, assumes 1 question at offset 12)
            qname, _ = parse_name(query_packet, 12)
            
            # (b) Domain name queried
            log(f"[QUERY] Received query from {client_addr} for {qname}")
            
            # (c) Resolution mode
            flags = struct.unpack('!H', query_packet[2:4])[0]
            if flags & 0x0100: # Check RD (Recursion Desired) bit
                log("[MODE] Recursive (Client requested, we will iterate)")
            else:
                log("[MODE] Iterative (Client did not request recursion, but we will iterate anyway)")
            
            # --- (i) Cache Check (Bonus F) ---
            if qname in CACHE:
                timestamp, ttl, cached_response_bytes = CACHE[qname]
                if (time.time() - timestamp) < ttl:
                    log(f"[CACHE] {qname}", "HIT")
                    # Modify the cached response to have the client's transaction ID
                    final_response = original_txid + cached_response_bytes[2:]
                    server_sock.sendto(final_response, client_addr)
                    continue # Skip to the next client query
                else:
                    log(f"[CACHE] {qname}", "EXPIRED")
                    del CACHE[qname]
            
            log(f"[CACHE] {qname}", "MISS")
            
            # --- 2. Perform Iterative Resolution ---
            total_start_time = time.time()
            final_response_packet = resolve_iterative(query_packet, qname)
            total_end_time = time.time()
            
            # (h) Total time to resolution
            total_time_ms = (total_end_time - total_start_time) * 1000
            log(f"[DONE] Total resolution time for {qname}: {total_time_ms:.2f} ms")
            
            # --- 3. Send Response to Client ---
            if final_response_packet:
                # Modify the final packet to have the client's original transaction ID
                final_response = original_txid + final_response_packet[2:]
                server_sock.sendto(final_response, client_addr)
            else:
                log(f"[FAIL] Sending SERVFAIL to {client_addr} for {qname}")
                # Build a SERVFAIL response
                # Flags: 0x8182 = Response, Recursion Desired, Recursion Available, RCODE=2 (Server Failure)
                fail_header = struct.pack('!HHHHHH', struct.unpack('!H', original_txid)[0], 0x8182, 1, 0, 0, 0)
                fail_response = fail_header + query_packet[12:] # Re-use original question
                server_sock.sendto(fail_response, client_addr)

        except Exception as e:
            log(f"[FATAL] Main loop error: {e}")

if __name__ == "__main__":
    main()

