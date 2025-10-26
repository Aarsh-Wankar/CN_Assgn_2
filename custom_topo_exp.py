from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
from mininet.nodelib import NAT

def customTopo():
    "Create a network with an explicitly configured NAT gateway."
    net = Mininet(controller=Controller, link=TCLink)

    net.addController('c0')

    # Add switches first
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')

    # FIX: Define the gateway IP and assign it explicitly to the NAT node.
    gateway_ip = '10.0.0.254'
    nat = net.addNAT(ip=f'{gateway_ip}/24', connect='s1')
    nat.configDefault()

    # Now use the explicitly defined gateway IP for the default routes.
    h1 = net.addHost('h1', ip='10.0.0.1/24', defaultRoute=f'via {gateway_ip}')
    h2 = net.addHost('h2', ip='10.0.0.2/24', defaultRoute=f'via {gateway_ip}')
    h3 = net.addHost('h3', ip='10.0.0.3/24', defaultRoute=f'via {gateway_ip}')
    h4 = net.addHost('h4', ip='10.0.0.4/24', defaultRoute=f'via {gateway_ip}')
    dns = net.addHost('dns', ip='10.0.0.5/24', defaultRoute=f'via {gateway_ip}')

    # Add links
    net.addLink(h1, s1, bw=100, delay='2ms')
    net.addLink(h2, s2, bw=100, delay='2ms')
    net.addLink(dns, s2, bw=100, delay='1ms')
    net.addLink(h3, s3, bw=100, delay='2ms')
    net.addLink(h4, s4, bw=100, delay='2ms')

    net.addLink(s1, s2, bw=100, delay='5ms')
    net.addLink(s2, s3, bw=100, delay='8ms')
    net.addLink(s3, s4, bw=100, delay='10ms')

    net.start()
    print(f"Configuring hosts to use local DNS node ({dns.IP()})...")
    for host in [h1, h2, h3, h4]:
        host.cmd(f'bash -c "echo nameserver {dns.IP()} > /etc/resolv.conf"')

    print("Topology created successfully!")
    print(f"NAT Gateway is running at {gateway_ip}")

    # --- RUN THE EXPERIMENT FOR PART B ---
    print("\n--- Starting DNS Performance Measurement (Part B) ---")
    hosts_to_test = {'h1': h1, 'h2': h2, 'h3': h3, 'h4': h4}
    
    for i in range(1, 5):
        hostname = f'h{i}'
        host_obj = hosts_to_test[hostname]
        domain_file = f'f_urls_h{i}.txt'
        
        print(f"\n>>> Running test on {hostname} using {domain_file}...")
        
        # Execute the measurement script on the host. The output will be
        # printed directly to your console.
        result = host_obj.cmd(f'python3 measure_dns.py {domain_file}')
        print(result)

    print("--- Measurement Complete ---\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    customTopo()
