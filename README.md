# pg2ipset

========
ABOUT 
========
(from original repo: https://github.com/ilikenwf/pg2ipset)

Information:

http://ipset.netfilter.org/

https://wiki.archlinux.org/index.php/Ipset

http://www.maeyanie.com/2008/12/efficient-iptables-peerguardian-blocklist/


pg2ipset takes the contents of PG2 IP Blocklists and outputs lists that
ipset under Linux can consume, for more efficient blocking than most 
other methods. 

The ipset-update.sh script helps import these and
plain text based blocklists easily, for scheduling via cron.


========
INSTALLATION
========

```make build && make install```

(or just run make as root)

========
CONFIGURATION
========

See the comments above each variable and array in the ipset-update.sh
script to configure it to block the ip lists of your choosing.

========
USAGE
========

To manually import from a .txt list from bluetack:

```cat /path/to/blocklist.txt | pg2ipset - - listname | ipset restore```


To manually import from a .gz list:

```zcat /path/to/blocklist.gz | pg2ipset - - listname | ipset restore```

	
To manually import a txt list of only IP addresses and/or CIDR ranges, 
make sure to remove all comments and empty lines, then do the following:

```awk '!x[$0]++' /path/to/blocklist.txt | sed -e "s/^/\-A\ \-exist\ listname\ /" | grep  -v \# | grep -v ^$ | ipset restore```


Help text:
	Usage: ./pg2ipset [<input> [<output> [<set name>]]]
	Input should be a PeerGuardian .p2p file, blank or '-' reads from stdin.
	Output is suitable for usage by 'ipset restore', blank or '-' prints to stdout.
	Set name is 'IPFILTER' if not specified.
	Example: curl http://www.example.com/guarding.p2p | ./pg2ipset | ipset restore

========
AUTOMATIC LIST UPDATING
========

Be friendly and don't update more than once every 24 hours. Bluetack likely
changes the obfuscated list URLS regularly, too.

```0 0 * * * sh /path/to/ipset-update.sh >/dev/null 2>&1```

