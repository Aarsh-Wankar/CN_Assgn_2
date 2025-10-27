# Computer Networks Assignment 2

Note : Due to their large size, we have excluded the PCAP files from this repository.

## Topology Setup

We recomment using the official mininet Virtual Machine Image along withe the `lxde` Desktop environment for running the scripts. Make sure the VM has access to Internet too. To setup the topology, please run 

```bash
sudo python basic_topo.py
```

To test if the topology has been setup porperly, please run 

```bash
pingall
```

## Default Resolver

Note : The filtered URL files have already been added to the repository (f_url files). The steps to obtain these have been incldued in the report.

Now we can send DNS requests to the default resolver using the below commands from the mininet CLI:

```bash
h1 python measure_dns_threaded.py f_urls_h1.txt
h2 python measure_dns_threaded.py f_urls_h2.txt
h3 python measure_dns_threaded.py f_urls_h3.txt
h4 python measure_dns_threaded.py f_urls_h4.txt
```

## Custom DNS Resolver

First setup the mininet topology with:

```bash
sudo python custom_topo.py
```
(Note that the only difference between basic_topo and custom_topo is the redirection of DNS requests to the custom resolver)

To setup the custom DNS resolver, open a terminal for it using `xterm dns` and then run 

```bash
python custom_dns_resolver.py
```

Now we can send DNS requests to the resolver using the below commands from the mininet CLI:

```bash
h1 python measure_dns_threaded.py f_urls_h1.txt
h2 python measure_dns_threaded.py f_urls_h2.txt
h3 python measure_dns_threaded.py f_urls_h3.txt
h4 python measure_dns_threaded.py f_urls_h4.txt
```
