#!/bin/bash

#Author: Martin
#Date: 10/11/2022

#Description
#The program is scanning a desired network, to alert the SOC monitoring team and to check their awarness.

#Usage: sochecker.sh <IP/CIDR>

echo "[+] Creating Folder for $1" 

ip=$(echo $1 | awk -F/ '{print $1}') #Had to seperate ip from CIDR because it was making directory errors

mkdir $ip 2>/dev/null

echo "[>>] Initiating scan on $1"

function scan1 #scanning multiple IP addresses at once

{
	
  	nmap -sL $1 | grep for | awk '{print $NF}' > Ip.lst #Making the list of the IP addresses to scan

	for i in $(cat Ip.lst | grep -v "[\.]0")

	do 

		echo "[>>] Scanning $i"

		nmap $i -Pn -p- -T5 > $2/$i &

		sleep 0.2

		if [ $(ps aux | egrep "nmap [0-9]{1,3}" | wc -l) -ge 130 ] #splitting the scan into 2 bulks so it won't crash

		then

			wait $(ps aux | egrep "nmap [0-9]{1,3}" | awk '{print $2}' | tail -1) #waiting for the last nmap process

		fi

	done

	wait $(ps aux | egrep "nmap ([0-9]{1,3}[\.]){3}[0-9]{1,3}" | awk '{print $2}' | tail -2 | head -1)
	
	mkdir $2/IPS
	
	for z in $( grep -iRn open $2 | awk -F: '{print $1}' | sort | uniq )
	
    do
    
        mv $z $2/IPS
    
    done
    
    rm $2/* 2>/dev/null
    
    for x in $(ls -l $2/IPS | awk '{print $NF}' | egrep "([0-9]{1,3}[\.]){3}[0-9]{1,3}" )
  
    do
      
      echo "[***]The open services that were found for $x are: "
      
      echo " "
      
      grep open $2/IPS/$x | awk '{print $1,$3}' 2>/dev/null
      
    done

}

function scan2 #function requiers high priv so use it only after switching to sudo

{

  sudo nmap -sN $1 | grep report | awk '{print $5}' > $2/IP.lst

  echo "[***]The following hosts that have been found are: "
  
  cat $2/IP.lst
  
  for i in $(cat $2/IP.lst)
  
  do
  
      echo "[>>]Scanning $i" 
  
      nmap -p- -Pn -T5 $i > $2/$i &
  
  done
  
  wait
  
  mkdir $2/IPS
	
	for z in $(grep -iRn open $2 | awk -F: '{print $1}' | sort | uniq)
	
    do
    
        mv $z $2/IPS
    
    done
  
  for x in $(ls -l $2/IPS | awk '{print $NF}' | egrep "([0-9]{1,3}[\.]){3}[0-9]{1,3}" )
  
  do
      
      echo "[***]The open services that were found for $x are: "
      
      echo " "
      
      grep open $2/IPS/$x | awk '{print $1,$3}' 2>/dev/null
      
  done
        
}

echo "[#]$(whoami) Please choose the method to scan the network: "

echo "1) Scan multiple hosts at once and skip host discovery."

echo "2) Discover online hosts and scan only them (requiers high priv)."

read -p "[#] Your choice: " ch

case $ch in

   1) scan1 $1 $ip 

;;

   2) scan2 $1 $ip

;;

   *) echo "[!!!]This is a wrong option, exiting..."
   
   exit

;;

esac

function enum #enumeration based on nse scripts

{
	
    
    for x in $(ls -l $1 | egrep -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
    
    do
    
        rm $1/$x 2>/dev/null
        
    done

	echo "Please choose an IP address to enumerate from the following addresses: "
	
	echo " "
	
	ls -l $1/IPS | awk '{print $NF}' | egrep "([0-9]{1,3}[\.]){3}[0-9]{1,3}"
	
	read -p "[#] Your choice: " ip
	
	echo " " 
	
	echo  "The services that are open of $ip are: "
	
	echo " "
	
	cat $1/IPS/$ip | grep open
	
	echo "The available enumeration NSE scripts are: "
	
	echo " "
	
	for z in $(cat $1/IPS/$ip | grep open | awk '{print $3}')
	
	do
	
	    locate *.nse | grep -i "enum" | grep $z | awk -F/ '{print $NF}'
	    
	done
	
	read -p "[#] Please choose an NSE script to enumerate: " scr
	
	echo " "
	
	echo "[>>]$(date  +"Time: %H:%M:%S Date: %d/%m/%y") Initiating enumeration using $scr on $ip" | tee -a $1/atk.log
	
	nmap $ip -Pn -sV --script=$scr
	
	wait
	
	echo " "
	
	echo "[***] Enumeration complete!"
	
}

function bf #brute force attack on the desired ip of the user

{
	
	echo "Please choose an IP address to enumerate from the following addresses: "
	
	echo " "
	
	ls -l $1/IPS | awk '{print $NF}' | egrep "([0-9]{1,3}[\.]){3}[0-9]{1,3}"
	
	read -p "[#] Your choice: " ip
	
	echo " " 
	
	echo  "The services that are open of $ip are: "
	
	echo " "
	
	cat $1/IPS/$ip | grep open
	
	read -p "[#] please type the service you would like to execute the attack on: " sr

	echo "admin,administrator,helpdesk,john,dave,matt,zeek,guest,host,msfadmin" | tr ',' '\n' > $1/usr.lst
	
	echo " "
	
	echo "[>>]$(date  +"Time: %H:%M:%S Date: %d/%m/%y") Initating brute force attack on $ip" | tee -a $1/atk.log
	
	echo " "
	
	hydra -L $1/usr.lst -P /usr/share/john/password.lst $ip $sr -vV
	
}

echo "[#]$(whoami) Please choose the attack method: "

echo "1) Enumeration (NSE Scripts)."

echo "2) Brute force attack (Hydra)."

read -p "[#] Your choice: " ch2

echo " " 

case $ch2 in

   1) enum $ip

;;

   2) bf $ip

;;

   *) echo "[!!!]This is a wrong option, exiting..."
   
   exit

;;

esac
