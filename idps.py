#! /usr/bin/env python
import socket, subprocess, netaddr
from netaddr import IPAddress

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

def scan_network(cidr):
	subprocess.call(["nmap", "-sP", cidr])

def main():
	hostip = find_hostip()
	hostname = find_hostname()
	print "Host Name:", hostname, "allocated IP:", hostip
	cidr = find_cidr(hostip)
	scan_network(cidr)
main()
