# NagiosNMAPscan
Automate and analyze NMAP-Scans by Nagios. Fork of original perl-script by Serg Belokamen and Zhivko Todorov (Released under GPL Licence)

It's recommended to use the additional NMAP-Argument "--open" to prevent NMAP Printing some filtered ports.

USAGE EXAMPLES:

Alowed ports are NULL:
script -n /usr/bin/nmap -i 192.168.1.1 -p e

Use Hostname (FQDN) as target:
script -n /usr/bin/nmap -f host.domain.tld -p e

More regular usage (allowed port is SSH: 22 and HTTP: 445):
script -n /usr/bin/nmap -i 192.168.1.1 -p 22,445

More usage (allowed port is SSH: 22 and HTTP: 445)
and port range 40000-45000 is excluded from scanning:
script -n /usr/bin/nmap -i 192.168.1.1 -p 22,445 -c '--exclude-ports 40000-45000'

By default nmap scans only 1000 most common used ports!!!
Please consider what type of scan you need!!!
