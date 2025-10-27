# Computer Networks Assignment 2

Note : Due to their large size, we have excluded the PCAP files from this repository. Please add them to the directory before running any scripts below.

We recomment using the official mininet Virtual Machine Image along withe the `lxde` Desktop environment for running the scripts. Make sure the VM has access to Internet too. To setup the topology, please run 

```bash
sudo python basic_topo.py
```

To test if the topology has been setup porperly, please run 

```bash
pingall
```

Note : The filtered URL files have already been added to the repository so you can skip the above two steps if needed.

To setup the custom DNS resolver, open a terminal for it using `xterm dns` and then run 

```bash
python custom_dns_resolver.py
```

Now we can send dns requests using `dig` or `nslookup` from the hosts and these will be redirected to our custom resolver. To check details of the experiments run, please view the report for the assignment. 
