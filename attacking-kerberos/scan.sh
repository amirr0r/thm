#!/bin/bash

VM="$1"
IP="$2"
# took this function from https://www.linuxjournal.com/content/validating-ip-address-bash-script
function valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

if [ ! -z $VM ] && [ ! -z $IP ]; then
	# 0. Check if it's a valid IP
	if ! $(valid_ip $IP); then echo "Wrong IP? $IP" && exit; fi
	# 1. Check if it's a Linux or a Windows VM 
	# 2. Create directory and go to it
	mkdir $IP
	cd $IP
	printf "# $IP\n\n## Enumeration\n\n### \`nmap\` scan\n\n## User\n\n## Foothold\n\n___\n\n## Privesc\n\n___\n" > README.md
	mkdir services
	mkdir img
	# 3. Start tmux
  	tmux start-server
  	tmux new-session -d -s $VM -n nmap
	echo "export TARGET=$IP" >> ~/.bashrc
	# 3.1 First nmap to get open ports
	tmux send-keys -t $VM:0 "nmap -oN ports.txt $IP -Pn &" C-m # -min-rate 5000 --max-retries 1
	# 3.2 Second nmap with services versions
	tmux send-keys -t $VM:0 "wait; nmap -sV -oN $IP.txt $IP -Pn &" C-m # -min-rate 5000 --max-retries 1
	# 3.3 Third nmap - exhaustive
	tmux send-keys -t $VM:0 "wait; nmap -sV -sC -p- -oN $IP-full-port-scan.txt $IP -Pn &" C-m # -min-rate 5000 --max-retries 1
	# 3.4 nmap - UDP
	tmux send-keys -t $VM:0 "wait; nmap -sU -oN UDP-scan.txt $IP -Pn &" C-m
	# 3.5 Last nmap - vuln
	tmux send-keys -t $VM:0 "wait; nmap -vvv --script vuln -oN vuln-scan.txt $IP -Pn &" C-m
	sleep 10
	# For each port ...
	i=1
	for p in $(cat ports.txt | grep -E "^[0-9]" | cut -d'/' -f1); do
		# Trying DNS Zone transfer if port 53
		if [ "$p" == "53" ]; then
			tmux new-window -t $VM:$i -n DNS
			tmux send-keys -t $VM:$i "dig axfr @$IP | tee services/53-dns.txt" C-m
			i=$((i+1))
		# gobuster if port 80 
		elif [ "$p" == "80" ]; then
			#tmux new-window -t $VM:$i -n dirb
			#tmux send-keys -t $VM:$i "dirb http://$IP -o services/80-http.txt" C-m
			tmux new-window -t $VM:$i -n HTTP
			#tmux send-keys -t $VM:$i "gobuster dir -u http://$IP -w /usr/share/dirb/wordlists/common.txt -o services/80-http.txt &" C-m
			tmux send-keys -t $VM:$i "gobuster dir -u http://$IP -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -x .txt -o services/80-http.txt &" C-m
			tmux send-keys -t $VM:$i "wait; nikto -h $IP | tee services/80-nikto.txt"
			i=$((i+1))
		# rpcclient if port 135
		elif [ "$p" == "135" ]; then
			tmux new-window -t $VM:$i -n RPC
			tmux send-keys -t $VM:$i "rpcclient -U '%' $IP | tee services/135-rpc.txt" C-m
			i=$((i+1))
		# smbclient if port 139
		elif [ "$p" == "139" ]; then
			tmux new-window -t $VM:$i -n SAMBA
			tmux send-keys -t $VM:$i "smbclient -L //$IP/ -U '%' | tee services/139-smbclient.txt" C-m
			tmux send-keys -t $VM:$i "wait; smbmap -H $TARGET -R | tee services/139-smbmap.txt"
			i=$((i+1))
			tmux new-window -t $VM:$i -n enum4linux
			tmux send-keys -t $VM:$i "enum4linux -a $IP | tee linux-enum.txt" C-m # enumerate SMB shares on both Windows and Linux systems
			i=$((i+1))
		# ldapsearch if port 389
		elif [ "$p" == "389" ]; then
			tmux new-window -t $VM:$i -n LDAP
			tmux send-keys -t $VM:$i "echo '$> ldapsearch -h $IP -x -s base namingcontexts' | tee services/ldap.txt" C-m
			tmux send-keys -t $VM:$i "ldapsearch -h $IP -x -s base namingcontexts | tee services/ldap.txt" C-m
			i=$((i+1))
		# gobuster if port 443
		elif [ "$p" == "443" ]; then
			tmux new-window -t $VM:$i -n HTTPS
			tmux send-keys -t $VM:$i "gobuster dir -u https://$IP -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -x .txt -k -o services/443-https.txt &" C-m
			tmux send-keys -t $VM:$i "wait; nikto -h $IP | tee services/443-nikto.txt"
		# smbclient if port 445
		elif [ "$p" == "445" ]; then
			tmux new-window -t $VM:$i -n SAMBA
			tmux send-keys -t $VM:$i "smbclient -L //$IP/ -U '%' | tee services/445-smbclient.txt" C-m
			tmux send-keys -t $VM:$i "wait; smbmap -H $TARGET -R | tee services/45-smbmap.txt"
			i=$((i+1))
			tmux new-window -t $VM:$i -n enum4linux
			tmux send-keys -t $VM:$i "enum4linux -a $IP | tee linux-enum.txt" C-m # enumerate SMB shares on both Windows and Linux systems
			i=$((i+1))
		# showmount if port 2049
		elif [ "$p" == "2049" ]; then
			tmux new-window -t $VM:$i -n NFS
			tmux send-keys -t $VM:$i "showmount -e $IP | tee services/2049-nfs.txt" C-m
			i=$((i+1))
		fi
	done
	tmux select-window -t $VM:0
	tmux attach-session -t $VM
else
	echo "Usage: bash autoscan.sh <VM_name> <IP> [speed]"
fi
