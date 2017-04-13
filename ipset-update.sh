#!/bin/bash

# ipset-update.sh (C) 2012-2015 Matt Parnell http://www.mattparnell.com
# Licensed under the GNU-GPLv2+

#where are our executables?

function whereisit {
[[ $(type -P "$@") ]] && echo "$@ is in PATH"  ||
    { echo "$@ is NOT in PATH" 1>&2; exit 1; }
}

whereisit ipset 
whereisit iptables 
whereisit pg2ipset 

IPSET=`type -P ipset`
IPTABLES=`type -P iptables`
PG2IPSET=`type -p pg2ipset`


# place to keep our cached blocklists
LISTDIR="/var/cache/blocklists"

# create cache directory for our lists if it isn't there
[ ! -d $LISTDIR ] && mkdir $LISTDIR

# countries to block, must be lcase
COUNTRIES_BL=(tr cn sa sy ru ua hk id jp)
COUNTRIES_WL=(us ca gb)


# bluetack lists to use - they now obfuscate these so get them from
# https://www.iblocklist.com/lists.php
BLUETACKALIAS=(DShield Hijacked DROP ForumSpam WebExploit Proxies BadSpiders CruzIT Zeus Palevo Malicious Malcode Adservers)
BLUETACK=(xpbqleszmajjesnzddhv usrcshglbiilevmyfhse zbdlwrqkabxbcppvrnos ficutxiwawokxlcyoeye ghlzqtqxnzctvvajwwag xoebmbyexwuiogmbyprb mcvxsnihddgutbjfbghy czvaehmjpsnwwttrdoyl ynkdjqsjyfmilsgbogqf erqajhwrxiuvjxqrrwfj npkuuhuxcsllnhoamkvm pbqcylkejciyhmwttify zhogegszwduurnvsyhdf) 
# ports to block tor users from
PORTS=(80 443 8080 21 12000 12001 12002 12003)

# remove old countries list
[ -f $LISTDIR/countries.txt ] && rm $LISTDIR/countries.txt

# remove the old tor node list
[ -f $LISTDIR/tor.txt ] && rm $LISTDIR/tor.txt

# enable bluetack lists?
ENABLE_BLUETACK=1

# enable country blocks?
ENABLE_COUNTRY_BL=0

#enable country whitelist for http/https?
ENABLE_COUNTRY_WL=0

# enable tor blocks?
ENABLE_TORBLOCK=1

# enable whitelist? add whitelist to $LISTDIR/whitelist/whitelist.txt
ENABLE_WHITELIST=0

# enable blacklist? add blacklist to $LISTDIR/blacklist.txt
ENABLE_BLACKLIST=1

#cache a copy of the $iptables rules
IPTABLES=$($iptables-save)

importList(){
  if [ -f $LISTDIR/$1.txt ] || [ -f $LISTDIR/$1.gz ]; then
	echo "Importing $1 blocks..."
	
	$IPSET create -exist $1 hash:net maxelem 4294967295
	$IPSET create -exist $1-TMP hash:net maxelem 4294967295
	$IPSET flush $1-TMP &> /dev/null

	#the second param determines if we need to use zcat or not
	if [ $2 = 1 ]; then
		zcat $LISTDIR/$1.gz | grep  -v \# | grep -v ^$ | grep -v 127\.0\.0 | pg2$IPSET - - $1-TMP | $IPSET restore
	else
		awk '!x[$0]++' $LISTDIR/$1.txt | grep  -v \# | grep -v ^$ |  grep -v 127\.0\.0 | sed -e "s/^/add\ \-exist\ $1\-TMP\ /" | $IPSET restore
	fi
	
	$IPSET swap $1 $1-TMP &> /dev/null
	$IPSET destroy $1-TMP &> /dev/null
	
	# only create if the $iptables rules don't already exist
	if ! echo $IPTABLES|grep -q "\-A\ INPUT\ \-m\ set\ \-\-match\-set\ $1\ src\ \-\j\ DROP"; then
          $iptables -I INPUT -m set --match-set $1 src -j ULOG --ulog-prefix "Blocked input $1"
          $iptables -A FORWARD -m set --match-set $1 src -j ULOG --ulog-prefix "Blocked fwd $1"
          $iptables -A FORWARD -m set --match-set $1 dst -j ULOG --ulog-prefix "Blocked fwd $1"
          $iptables -I OUTPUT -m set --match-set $1 dst -j ULOG --ulog-prefix "Blocked out $1"

	  $iptables -I INPUT -m set --match-set $1 src -j DROP
	  $iptables -A FORWARD -m set --match-set $1 src -j DROP
	  $iptables -A FORWARD -m set --match-set $1 dst -j REJECT
	  $iptables -I OUTPUT -m set --match-set $1 dst -j REJECT
	fi
  else
	echo "List $1.txt does not exist."
  fi
}

if [ $ENABLE_BLUETACK = 1 ]; then
  # get, parse, and import the bluetack lists
  # they are special in that they are gz compressed and require
  # pg2$IPSET to be inserted

# Stop fail2ban to ensure rules are sent to top of list

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
	  cat /tmp/$country_bl.txt >> $LISTDIR/country_blacklist.txt
	  rm /tmp/$country_bl.txt
	fi
  done
  
  importList "country_blacklist" 0
fi

if [ $ENABLE_TORBLOCK = 1 ]; then
  # get the tor lists and cat them into a single file
  for ip in $(dig +short myip.opendns.com @resolver1.opendns.com; echo $4); do
	for port in ${PORTS[@]}; do
	  if [ eval $(wget --quiet -O /tmp/$port.txt https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=$ip&port=$port) ]; then
		cat /tmp/$port.txt >> $LISTDIR/tor.txt
		rm /tmp/$port.txt
	  fi
	done
  done 
  
  importList "tor" 0
fi

if [ $ENABLE_BLACKLIST = 1 ]; then
  importList "blacklist" 0
fi


importWhitelists(){
if [[ $ENABLE_WHITELIST = 1 ]]; then
	  if [ -f $LISTDIR/whitelist/whitelist.txt ]; then
		echo "Importing whitelist accepts..."
		
		$IPSET create -exist whitelist hash:net maxelem 4294967295
		$IPSET create -exist whitelist-TMP hash:net maxelem 4294967295
		$IPSET flush whitelist-TMP &> /dev/null

		awk '!x[$0]++' $LISTDIR/whitelist/whitelist.txt | grep  -v \# | grep -v ^$ |  grep -v 127\.0\.0 | sed -e "s/^/add\ \-exist\ whitelist\-TMP\ /" | $IPSET restore
		
		$IPSET swap whitelist whitelist-TMP &> /dev/null
		$IPSET destroy whitelist-TMP &> /dev/null
		
		# only create if the $iptables rules don't already exist
		if ! echo $IPTABLES|grep -q "whitelist"; then
		  $iptables -I INPUT -m set --match-set whitelist src -p tcp -m multiport --dports http,https -j ACCEPT
		  $iptables -I OUTPUT -m set --match-set whitelist dst -p tcp -m multiport --sports http,https -j ACCEPT
		fi

	  else
		echo "List whitelist.txt does not exist."
	  fi
fi
if [[ $ENABLE_COUNTRY_WL = 1 ]]; then
  for country_wl in ${COUNTRIES_WL[@]}; do
        if [ eval $(wget --quiet -O /tmp/$country_wl.txt http://www.ipdeny.com/ipblocks/data/countries/$country_wl.zone) ]; then
          cat /tmp/$country_wl.txt >> $LISTDIR/country_whitelist.txt
          rm /tmp/$country_wl.txt
        fi
  done
                $IPSET create -exist country_whitelist hash:net maxelem 4294967295
                $IPSET create -exist country_whitelist-TMP hash:net maxelem 4294967295
                $IPSET flush country_whitelist-TMP &> /dev/null

		awk '!x[$0]++' $LISTDIR/country_whitelist.txt | grep  -v \# | grep -v ^$ |  grep -v 127\.0\.0 | sed -e "s/^/add\ \-exist\ country_whitelist\-TMP\ /" | $IPSET restore

                $IPSET swap country_whitelist country_whitelist-TMP &> /dev/null
                $IPSET destroy country_whitelist-TMP &> /dev/null

                # only create if the $iptables rules don't already exist
                if ! echo $IPTABLES|grep -q "country_whitelist"; then
                  $iptables -I INPUT -m set --match-set country_whitelist src -p tcp -m multiport --dports http,https -j ACCEPT
                  $iptables -I OUTPUT -m set --match-set country_whitelist dst -p tcp -m multiport --sports http,https -j ACCEPT
                fi

          else
                echo "Something went wrong while configuring the country_whitelist"
          fi
}

importWhitelists
