#! /usr/bin/env python
import os, socket, subprocess, netaddr, nmap, copy
import signal, sys ,re
from netaddr import IPAddress
from time import sleep
###########Global variables##########
first_scan_hosts = []
blocked_mac = []
#####################################

def dottedQuadToNum(ip):
        "convert decimal dotted quad string to long integer"
        hexn = ''.join(["%02X" % long(i) for i in ip.split('.')])
        return long(hexn, 16)

def numToDottedQuad(n):
        "convert long int to dotted quad string"
        d = 256 * 256 * 256
        q = []
        while d > 0:
                m,n = divmod(n,d)
                q.append(str(m))
                d = d/256
        return '.'.join(q)

def find_hostname():
	return socket.gethostname()

def find_hostip():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.connect(("google.com",80))
	hostip = sock.getsockname()[0]
	sock.close()
	return hostip

def find_cidr(hostip):
	proc = subprocess.Popen('ifconfig',stdout=subprocess.PIPE)
	while True:
        	line = proc.stdout.readline()
	        if hostip.encode() in line:
        	        info = line.split(' ')
                	break
#	print 'Netmask is:'
#	print info[-4]
	netmask = info[-4]
	maskbits = IPAddress(netmask).netmask_bits()
	ipquad = dottedQuadToNum(hostip);
	netmask = dottedQuadToNum(netmask);
	netipquad = ipquad & netmask;
	netip = numToDottedQuad(netipquad);
	cidr = netip + '/'+ str(maskbits)
#	print 'Netmask bits'
#	print maskbits
#	print 'Net address'
#	print netip
	print 'CIDR Notation'
	print cidr
	return cidr

def scan_network(cidr, discovered_hosts):
	nohdiscovered = 0

	nm = nmap.PortScanner()
	nm.scan(hosts=cidr, arguments='-n -sP -PE')
	for item in nm.all_hosts():
		discovered_hosts.append(item)
		nohdiscovered = nohdiscovered + 1;
	return nohdiscovered

def updadte_known_host(second_scan_hosts, snohosts):
	print "Updating the known hosts list"
	global first_scan_hosts
	first_scan_hosts = list(second_scan_hosts)
	fnohosts = snohosts 
	return fnohosts

def find_mac(host_ip):
#Assuming use of arping on Red Hat Linux
	p = subprocess.Popen("/usr/sbin/arping -c 2 %s" % host_ip, shell=True, stdout=subprocess.PIPE)
	out = p.stdout.read()
	result = out.split()
	pattern = re.compile(":")
	for item in result:
		if re.search(pattern, item):
			mac = item
			break	
	return mac

def block_host(host_ip):
	#Here we will find the MAC address as IP of the same host may be change
	#To remove this user may have to open the iptables and remove the rule for now
	global blocked_mac
	mac = find_mac(host_ip)	
	print "Mac address for the new host", mac
	blocked_mac.append(mac)
	cmd = "iptables -A INPUT -m mac --mac-source " + mac + " -j DROP"
	print "IPtable command:", cmd	
	os.system(cmd)
	print "Host successfull blocked, please remove the rule from iptables to allow"

def check_new_host(second_scan_hosts, fnohosts, snohosts):	
	ftmp_idx = 0
	stmp_idx = 0
	match = 0
	tmp = 0
	host_removed = 0
	host_added = 0
	new_host = []
	no_new_host = 0
	global first_scan_hosts 
	wrong_usr_inp_flag = 0
#	if first_scan_hosts == second_scan_hosts:
		#Do Nothing
#	while tmp < snohosts:
#		print second_scan_hosts[tmp]
#		tmp = tmp + 1

#Logic to check if any new IP address is introduced
	while stmp_idx != snohosts:
		ftmp_idx = 0
		while ftmp_idx != fnohosts:
			match = 0
			if second_scan_hosts[stmp_idx] == first_scan_hosts[ftmp_idx]:
#				print 'Match found for the IP:', second_scan_hosts[stmp_idx]
				match = 1
				break
			ftmp_idx = ftmp_idx + 1
		if match == 0:
			mac = find_mac(second_scan_hosts[stmp_idx])
			if mac not in blocked_mac:
				print "************ALERT!!New Host Discovered***************"
				print second_scan_hosts[stmp_idx]
				new_host.append(second_scan_hosts[stmp_idx])
				no_new_host = no_new_host + 1
				#The script will discover hosts based on first come on first serve
				host_added = 1
		stmp_idx = stmp_idx + 1
	if host_added == 1:
		while wrong_usr_inp_flag == 0:
			tmp = 0
			print "Number of new hosts", no_new_host
			while tmp < no_new_host:
				print "New Host is:", new_host[tmp]
				user_ch = raw_input("Do you want to block this new host (y/n)")
				if user_ch == 'y':
					#Use IP tables to block this
					print "Blocking the IPaddress and keeping the known host list as it is"
					block_host(new_host[tmp])
					print "Continuing monitoring...."
					wrong_usr_inp_flag = 1
				elif user_ch == 'n':
					#Update the list by adding this new host to known host list
					fnohosts = updadte_known_host(second_scan_hosts, snohosts)
					print "Updated known hosts are"
					tmp = 0
					while tmp < fnohosts:
						print first_scan_hosts[tmp]
						tmp = tmp + 1
					wrong_usr_inp_flag = 1
				else:
					print 'Wrong choice entered, please try again.'
					wrong_usr_inp_flag = 0
				tmp = tmp + 1
	stmp_idx = 0
	ftmp_idx = 0	
	tmp = 0
#Logic to check if any IP address is removed
	while ftmp_idx != fnohosts:
		stmp_idx = 0
		while stmp_idx != snohosts:
			match = 0
			if first_scan_hosts[ftmp_idx] == second_scan_hosts[stmp_idx]:
				match = 1
				break
			stmp_idx = stmp_idx + 1
		if match == 0:
			print "************Host is been removed***************"
			print first_scan_hosts[ftmp_idx]
			host_removed = 1
		ftmp_idx = ftmp_idx + 1
	if host_removed == 1:
		fnohosts = updadte_known_host(second_scan_hosts, snohosts)
		print "Updated known hosts are"
		tmp = 0
		while tmp < fnohosts:
			print first_scan_hosts[tmp]
			tmp = tmp + 1
#We need to return the updated number of hosts which are in the known host list
	return fnohosts

def main():
	inf_cnt = 0
	tmp_idx = 0
	fnohosts = 0
	snohosts = 0
	global first_scan_hosts
	second_scan_hosts = []
	
	hostip = find_hostip()
	hostname = find_hostname()

	print "Press Ctrl+C to exit IDPS"
	print "Host Name:", hostname, "allocated IP:", hostip
	while inf_cnt < 2:
		tmp_idx = 0
#############The following logic will print the output of first scan and will print the result only if a new hosts is discovered##############
		if inf_cnt == 0:
			cidr = find_cidr(hostip)
			fnohosts = scan_network(cidr, first_scan_hosts)
			print "No of hosts discovered:", fnohosts
			print "Hosts discovered"
			while tmp_idx < fnohosts:
				print first_scan_hosts[tmp_idx]
				tmp_idx = tmp_idx + 1
			inf_cnt = inf_cnt + 1
		if inf_cnt == 1:
			second_scan_hosts = []
			print 'Looking for other hosts...'
			snohosts = 0
			snohosts = scan_network(cidr, second_scan_hosts)			
			fnohosts = check_new_host(second_scan_hosts, fnohosts, snohosts)	
#			print "New list of known hosts is"
#			tmp = 0
#			while tmp < fnohosts:
#				print first_scan_hosts[tmp]
#				tmp = tmp + 1
		sleep(5)
def signal_handler(signal, frame):
        print("Terminating..IDPS")
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)
main()
