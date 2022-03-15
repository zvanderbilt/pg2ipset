#!/bin/bash

# ipset-update.sh (C) 2012-2015 Matt Parnell http://www.mattparnell.com
# Licensed under the GNU-GPLv2+

#where are our executables?

function whereisit {
	[[ $(type -P "$@") ]]  ||
		{ echo "$@ is NOT in PATH" 1>&2; exit 1; }
	}

whereisit ipset 
whereisit iptables 
whereisit pg2ipset 
whereisit jq 

IPSET=`type -P ipset`
IPTABLES=`type -P iptables`
PG2IPSET=`type -P pg2ipset`
JQ=`type -P jq`


# place to keep our cached blocklists
LISTDIR="/var/cache/blocklists"

# create cache directory for our lists if it isn't there
[ ! -d $LISTDIR ] && mkdir $LISTDIR

# countries to block, must be lowercase
COUNTRIES_BL=(tr cn sa sy ru ua hk id jp)
COUNTRIES_WL=(us ca gb)


# bluetack lists to use - they now obfuscate these so get them from
# https://www.iblocklist.com/lists.php
BLUETACKALIAS=(DShield Hijacked DROP ForumSpam WebExploit Proxies BadSpiders CruzIT Zeus Palevo Malicious Malcode Adservers)
BLUETACK=(xpbqleszmajjesnzddhv usrcshglbiilevmyfhse zbdlwrqkabxbcppvrnos ficutxiwawokxlcyoeye ghlzqtqxnzctvvajwwag xoebmbyexwuiogmbyprb mcvxsnihddgutbjfbghy czvaehmjpsnwwttrdoyl ynkdjqsjyfmilsgbogqf erqajhwrxiuvjxqrrwfj npkuuhuxcsllnhoamkvm pbqcylkejciyhmwttify zhogegszwduurnvsyhdf) 
# ports to block tor users from
PORTS=(80 443)

# remove old countries list
[ -f $LISTDIR/countries.txt ] && rm $LISTDIR/countries.txt

# remove the old tor node list
[ -f $LISTDIR/tor.txt ] && rm $LISTDIR/tor.txt

# remove the old ec2 range list
[ -f $LISTDIR/ec2-ranges.txt ] && rm $LISTDIR/ec2-ranges.txt

# remove the old gcp node list
[ -f $LISTDIR/gcp.txt ] && rm $LISTDIR/gcp-ranges.txt

# remove the old msft node list
[ -f $LISTDIR/azure.txt ] && rm $LISTDIR/azure-ranges.txt

# remove the old digitalocean node list
[ -f $LISTDIR/do-ranges.txt ] && rm $LISTDIR/do-ranges.txt


# enable bluetack lists?
ENABLE_BLUETACK=0

# enable country blocks?
ENABLE_COUNTRY_BL=0

#enable country whitelist for http/https?
ENABLE_COUNTRY_WL=0

# enable tor blocks?
ENABLE_TORBLOCK=0

# enable whitelist? add whitelist to $LISTDIR/whitelist/whitelist.txt
ENABLE_WHITELIST=0

# enable blocklist? add blocklist to $LISTDIR/blocklist.txt
ENABLE_BLOCKLIST=0

ENABLE_DO_BLOCKLIST=0

ENABLE_EC2_BLOCKLIST=0

ENABLE_GCP_BLOCKLIST=0

ENABLE_AZURE_BLOCKLIST=0

#cache a copy of the $IPTABLES rules
IPTABLES=$(iptables-save)

# Ensure Country Whitelist is sent to bottom of ipset-update.sh iptables rules

if [[ $ENABLE_COUNTRY_WL = 1 ]]; then
	for country_wl in ${COUNTRIES_WL[@]}; do
		if [ eval $(wget --quiet -O /tmp/$country_wl.txt http://www.ipdeny.com/ipblocks/data/countries/$country_wl.zone) ]; then
			cat /tmp/$country_wl.txt >> $LISTDIR/country_whitelist.txt
			rm /tmp/$country_wl.txt
		fi
	done
	ipset create -exist country_whitelist hash:net maxelem 4294967295
	ipset create -exist country_whitelist-TMP hash:net maxelem 4294967295
	ipset flush country_whitelist-TMP &> /dev/null

	awk '!x[$0]++' $LISTDIR/country_whitelist.txt | grep  -v \# | grep -v ^$ |  grep -v 127\.0\.0 | sed -e "s/^/add\ \-exist\ country_whitelist\-TMP\ /" | ipset restore

		ipset swap country_whitelist country_whitelist-TMP &> /dev/null
	ipset destroy country_whitelist-TMP &> /dev/null

		# only create if the IPTABLES rules don't already exist
		if ! echo $IPTABLES|grep -q "country_whitelist"; then
			iptables -A INPUT -m set --match-set country_whitelist src -p tcp -m multiport --dports http,https -j ACCEPT
			iptables -A OUTPUT -m set --match-set country_whitelist dst -p tcp -m multiport --sports http,https -j ACCEPT
		fi
		if [[ $(ps -ef | grep -v grep | grep fail2ban | wc -l) == 1 ]]; then
			service fail2ban restart
		fi
fi

importList(){
	if [ -f $LISTDIR/$1.txt ] || [ -f $LISTDIR/$1.gz ]; then
		echo "Importing $1 blocks..."

		ipset create -exist $1 hash:net maxelem 4294967295
		ipset create -exist $1-TMP hash:net maxelem 4294967295
		ipset flush $1-TMP &> /dev/null

	#the second param determines if we need to use zcat or not
	if [ $2 = 1 ]; then
		zcat $LISTDIR/$1.gz | grep  -v \# | grep -v ^$ | grep -v 127\.0\.0 | pg2ipset - - $1-TMP | ipset restore
		else
			awk '!x[$0]++' $LISTDIR/$1.txt | grep  -v \# | grep -v ^$ |  grep -v 127\.0\.0 | sed -e "s/^/add\ \-exist\ $1\-TMP\ /" | ipset restore
	fi

			ipset swap $1 $1-TMP &> /dev/null
			ipset destroy $1-TMP &> /dev/null

	# only create if the IPTABLES rules don't already exist
	if ! echo $IPTABLES|grep -q "\-A\ INPUT\ \-m\ set\ \-\-match\-set\ $1\ src\ \-\j\ DROP"; then
		iptables -I INPUT -m set --match-set $1 src -j LOG --log-prefix "Blocked input $1"
		iptables -A FORWARD -m set --match-set $1 src -j LOG --log-prefix "Blocked fwd $1"
		iptables -A FORWARD -m set --match-set $1 dst -j LOG --log-prefix "Blocked fwd $1"
		iptables -I OUTPUT -m set --match-set $1 dst -j LOG --log-prefix "Blocked out $1"

		iptables -I INPUT -m set --match-set $1 src -j DROP
		iptables -A FORWARD -m set --match-set $1 src -j DROP
		iptables -A FORWARD -m set --match-set $1 dst -j REJECT
		iptables -I OUTPUT -m set --match-set $1 dst -j REJECT
	fi
else
	echo "List $1.txt does not exist."
	fi
}

if [ $ENABLE_BLUETACK = 1 ]; then
	# get, parse, and import the bluetack lists
	# they are special in that they are gz compressed and require
	# pg2ipset to be inserted

	i=0
	for list in ${BLUETACK[@]}; do  
		if [ eval $(wget --quiet -O /tmp/${BLUETACKALIAS[i]}.gz http://list.iblocklist.com/?list=$list&fileformat=p2p&archiveformat=gz) ]; then
			mv /tmp/${BLUETACKALIAS[i]}.gz $LISTDIR/${BLUETACKALIAS[i]}.gz
		else
			echo "Using cached list for ${BLUETACKALIAS[i]}."
		fi

		echo "Importing bluetack list ${BLUETACKALIAS[i]}..."

		importList ${BLUETACKALIAS[i]} 1

		i=$((i+1))

	done

fi

if [ $ENABLE_COUNTRY_BL = 1 ]; then
	# get the country lists and cat them into a single file
	for country_bl in ${COUNTRIES_BL[@]}; do
		if [ eval $(wget --quiet -O /tmp/$country_bl.txt http://www.ipdeny.com/ipblocks/data/countries/$country_bl.zone) ]; then
			cat /tmp/$country_bl.txt >> $LISTDIR/country_blocklist.txt
			rm /tmp/$country_bl.txt
		fi
	done

	importList "country_blocklist" 0
fi

if [ $ENABLE_TORBLOCK = 1 ]; then
	# get the tor lists and cat them into a single file
	for ip in $(curl 'https://api.ipify.org?format=txt'); do
		for port in ${PORTS[@]}; do
			if [ eval $(wget --quiet -O /tmp/$port.txt https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=$ip&port=$port) ]; then
				cat /tmp/$port.txt >> $LISTDIR/tor.txt
				rm /tmp/$port.txt
			fi
		done
	done 

	importList "tor" 0
fi

if [[ $ENABLE_BLOCKLIST = 1 ]]; then
	importList "blocklist" 0
fi

if [[ $ENABLE_EC2_BLOCKLIST = 1 ]]; then

	curl -s https://ip-ranges.amazonaws.com/ip-ranges.json -o /tmp/ec2-ip-ranges.json

	cat /tmp/ec2-ip-ranges.json | jq -r '.prefixes[] | select(.service=="EC2") | .ip_prefix' > $LISTDIR/ec2-ranges.txt

	echo "Importing ec2 ranges list..."

	importList "ec2-ranges"  0
fi

if [[ $ENABLE_GCP_BLOCKLIST = 1 ]]; then

	curl -s https://www.gstatic.com/ipranges/cloud.json -o /tmp/gcp-ip-ranges.json

	cat /tmp/gcp-ip-ranges.json | jq -r '.prefixes[] | .ipv4Prefix' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9][0-9]?" > $LISTDIR/gcp-ranges.txt

	echo "Importing gcp ranges list..."

	importList "gcp-ranges"  0
fi

if [[ $ENABLE_AZURE_BLOCKLIST = 1 ]]; then

	download_link=$(curl -sS https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519 | egrep -o 'https://download.*?\.json' | uniq | grep -v refresh)

	if [ $? -eq 0 ]
	then
		wget --quiet -O /tmp/azure-ip-ranges.json $download_link ; echo "Latest Azure IP list downloaded"
		echo "Importing azure ranges list..."
		cat /tmp/azure-ip-ranges.json | jq -rj '.values[].properties.addressPrefixes' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9][0-9]?" > $LISTDIR/azure-ranges.txt
		importList "azure-ranges"  0
	else 
		echo "Azure IP list download failed"
	fi

fi


if [[ $ENABLE_TENABLE_BLOCKLIST = 1 ]]; then

	curl -s https://docs.tenable.com/ip-ranges/data.json -o /tmp/tenable-ip-ranges.json

	cat /tmp/tenable-ip-ranges.json | jq -r '.prefixes[] | select(.service=="tenable-scanners") | .ip_prefix' > $LISTDIR/tenable-ranges.txt

	echo "Importing tenable ranges list..."

	importList "tenable-ranges"  0
fi



if [[ $ENABLE_DO_BLOCKLIST = 1 ]]; then

	curl -s https://raw.githubusercontent.com/SecOps-Institute/Digitalocean-ASN-and-IPs-List/master/digitalocean_ip_cidr_blocks.lst -o  $LISTDIR/do-ranges.txt

	echo "Importing DO ranges list..."

	importList "do-ranges"  0
fi



importWhitelist(){
	if [[ $ENABLE_WHITELIST = 1 ]]; then
		if [ -f $LISTDIR/whitelist/whitelist.txt ]; then
			echo "Importing whitelist accepts..."

			ipset create -exist whitelist hash:net maxelem 4294967295
			ipset create -exist whitelist-TMP hash:net maxelem 4294967295
			ipset flush whitelist-TMP &> /dev/null

			awk '!x[$0]++' $LISTDIR/whitelist/whitelist.txt | grep  -v \# | grep -v ^$ |  grep -v 127\.0\.0 | sed -e "s/^/add\ \-exist\ whitelist\-TMP\ /" | ipset restore

				ipset swap whitelist whitelist-TMP &> /dev/null
			ipset destroy whitelist-TMP &> /dev/null

		# only create if the iptables rules don't already exist
		if ! echo iptables|grep -q "whitelist"; then
			iptables -I INPUT -m set --match-set whitelist src -p tcp -m multiport --dports http,https -j ACCEPT
			iptables -I OUTPUT -m set --match-set whitelist dst -p tcp -m multiport --sports http,https -j ACCEPT
		fi

	else
		echo "List whitelist.txt does not exist."
		fi
	fi
}

if [[ $ENABLE_WHITELIST = 1 ]]; then
	importList "whitelist" 0
fi
