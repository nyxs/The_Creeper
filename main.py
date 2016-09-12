import os
import sys
import json
import logging
import subprocess
import threading
import argparse
import shlex
import shutil
import re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
try:
	import requests
except:
	try:
		subprocess.call('sudo pip install requests')
	except:
		print "Request library not found, please install it before proceeding\n"
		sys.exit()
from datetime import datetime
from time import strftime

subsandip_arr = []
subsandip_dict = {}
sum_dict = {}
subslist = ""
domain = ""

class Colors:
	def __init__(self):
		self.data = []
	BLACK = '\033[1m\033[30m'
	RED = '\033[1m\033[31m'
	GREEN = '\033[1m\033[32m'
	YELLOW = '\033[1m\033[33m'
	BLUE = '\033[1m\033[34m'
	MAGENTA = '\033[1m\033[35m'
	CYAN = '\033[1m\033[36m'
	WHITE = '\033[1m\033[37m'
	RESET = '\033[0m'

def adds_if_not_exists(the_ip, the_domain="", dns="", the_port="", flag=""):
	the_domain = str(the_domain)
	the_ip = str(the_ip)
	the_port = str(the_port)
	found_ip = False
	found_domain = False
	msg = ""

	if len(sum_dict) > 0:
		if the_ip in sum_dict:
			found_ip = True

			if not the_domain == "":
				for key, val in sum_dict[the_ip]['Domains']:
					if val == the_domain:
						found_domain = True
						print "\n" + the_domain + " with ip " + the_ip + " is already exists"
						break
					else: #still couldn't find the domain in sum_dict
						found_domain = False

				if found_domain == False:
					sum_dict[the_ip]['counter'] += 1
					sum_dict[the_ip]['Domains'][sum_dict[the_ip]['counter']] = the_domain
					print "[" + Colors.GREEN + "+" + Colors.RESET + "]" + Colors.GREEN + " The domain " + the_domain + " added to the ip " + the_ip + "\n" + Colors.RESET
				else: #found the domain in sum_dict
					found_domain = True
			else: #the domain is empty
				pass

			if not the_port == "" and not flag == "":
				for key, val in sum_dict[the_ip]['Ports']:
					if not the_port in key: #the port hasn't been registered yet
						sum_dict[the_ip]['Ports'][the_port] = flag
						print "[" + Colors.GREEN + "+" + Colors.RESET + "]" + Colors.GREEN + " The prot: " + the_port + " has the flag " + flag + " on " + the_ip + "\n" + Colors.RESET
					else: #the port is already exist
						if not flag in val:
							sum_dict[the_ip]['Ports'][the_port] += ", " + flag
							print "[" + Colors.GREEN + "+" + Colors.RESET + "]" + Colors.GREEN + " The prot: " + the_port + " now got the flag " + flag + " on " + the_ip + "\n" + Colors.RESET

			if not dns == "":
				for d in dns:
					if not d in sum_dict[the_ip]['Dns']:
						sum_dict[the_ip]['Dns'].append(d)
						print "[" + Colors.GREEN + "+" + Colors.RESET + "]" + Colors.GREEN + " The DNS " + d + " added to the domain: " + domain + "\n" + Colors.RESET
		
		else: #the IP is not in sum_dict
			found_ip = False
	else: #Nothing in sum_dict
		found_ip = False

	if found_ip == False:
		sum_dict[the_ip] = {}
		sum_dict[the_ip]['counter'] = 0
		sum_dict[the_ip]['Domains'] = {}
		sum_dict[the_ip]['Ports'] = {}
		sum_dict[the_ip]['Dns'] = []

		if not the_domain == "":
			sum_dict[the_ip]['counter'] += 1
			sum_dict[the_ip]['Domains'][sum_dict[the_ip]['counter']] = the_domain
			print "[" + Colors.GREEN + "+" + Colors.RESET + "]" + Colors.GREEN + " The domain " + the_domain + " added to the ip " + the_ip + "\n" + Colors.RESET

		if not the_port in sum_dict[the_ip]['Ports'] and not the_port == "":
			sum_dict[the_ip]['Ports'].append(the_port)
			print "[" + Colors.GREEN + "+" + Colors.RESET + "]" + Colors.GREEN + " The prot: " + the_port + " is open on " + the_ip + "\n" + Colors.RESET

		if not dns == "":
			for d in dns:
				if not d in sum_dict[the_ip]['Dns']:
					sum_dict[the_ip]['Dns'].append(d)
					print "[" + Colors.GREEN + "+" + Colors.RESET + "]" + Colors.GREEN + " The DNS " + d + " added to the domain: " + domain + "\n" + Colors.RESET
		
def get_dns(address):
	proc1 = subprocess.Popen(shlex.split('whois ' + address),stdout=subprocess.PIPE)
	proc2 = subprocess.Popen(shlex.split('grep "Name Server"'),stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc3 = subprocess.Popen(shlex.split('grep -v "   N"'),stdin=proc2.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	proc1.stdout.close()
	proc2.stdout.close()
	out,err=proc3.communicate()
	dns_arr = out.replace("Name Server: ", '').split("\n")
	dns_arr.remove('')
	dns_arr = sorted(dns_arr)
	return dns_arr

def get_ip(minimum, maximum):
	for line in range(minimum, maximum):
		get_ip_from_domain(subslist[line].strip() + '.' + domain)

def get_hosts(current_ip, minimum, maximum):
	for end in range(minimum, maximum):
		full_ip = current_ip + str(end)
		ip_arr = full_ip.split('.')
		ip_arr.reverse()
		ip = '.'.join(ip_arr) + ".in-addr.arpa"
		answer = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=ip , qtype='PTR')), timeout=2, verbose=False)
		counter = 0

		try:
			dns_rcode = answer.sprintf('%DNS.rcode%')
			if  dns_rcode== "ok":
				while True:
					try:
						scapy_domain = str(answer[DNS].an[counter].rdata)[:-1]
						if '.' in scapy_domain:
							adds_if_not_exists(full_ip, the_domain=scapy_domain)
							counter += 1
					except:
						break
			else:
				if verbose == True:
					print "\n[" + Colors.RED + "-" + Colors.RESET + "]" + Colors.RED + " Couldn't find any hosts for " + str(full_ip) + "\n" + Colors.RESET
		except:
			if verbose == True:
				print "\n[" + Colors.RED + "-" + Colors.RESET + "]" + Colors.RED + " Couldn't find any hosts for " + str(full_ip) + "\n" + Colors.RESET
		
		try:
			ans = socket.gethostbyaddr(full_ip)
			if not full_ip in ans[0]:
				adds_if_not_exists(full_ip, the_domain=ans[0])
		except:
			if verbose == True:
				print "\n[" + Colors.RED + "-" + Colors.RESET + "]" + Colors.RED + " Couldn't find any hosts for " + str(full_ip) + "\n" + Colors.RESET

def start_threads_for_port_scanning(ip):
	print "[" + Colors.MAGENTA + "!" + Colors.RESET + "]" + Colors.MAGENTA + " Working on " + ip + Colors.RESET
	list_of_threads = []
	thread_counter = 0
	num_of_ports = 65536

	if threads > 1:
		num_ports_for_thread = num_of_ports / threads
		num_of_ports_for_last_thread = num_of_ports - (num_ports_for_thread * (threads - 1))

		for thread_counter in range(1, threads):
			exec("thread%d = myThread(func=\"get ports\", minimum=(thread_counter-1)*num_ports_for_thread, maximum=thread_counter*num_ports_for_thread, ip=ip)" % (thread_counter))
			exec("thread%d.start()" % (thread_counter))
			exec("list_of_threads.append(thread%d)" % (thread_counter))

		if num_of_ports_for_last_thread > 0:
			thread_counter += 1
			# last thread handling
			exec("thread%d = myThread(func=\"get ports\", minimum=number_of_subs - num_of_ports_for_last_thread, maximum=number_of_subs, ip=ip)" % (thread_counter))
			exec("thread%d.start()" % (thread_counter))
			exec("list_of_threads.append(thread%d)" % (thread_counter))
	else:
		num_ports_for_thread = num_of_ports
		for thread_counter in range(1, threads + 1):
			exec("thread%d = myThread(func=\"get ports\", minimum=(thread_counter-1)*num_ports_for_thread, maximum=thread_counter*num_ports_for_thread, ip=ip)" % (thread_counter))
			exec("thread%d.start()" % (thread_counter))
			exec("list_of_threads.append(thread%d)" % (thread_counter))

	for t in list_of_threads:
		t.join()

def scan_ports(dst_ip, min_port, max_port):
	for port in range(min_port, max_port):
		SYNpkt = sr1(IP(dst=dst_ip)/TCP(sport=RandShort(), dport=port, flags="S"), timeout=2, verbose=False)
		if not "nonetype" in str(type(SYNpkt)).lower():
			flag = SYNpkt.sprintf('%TCP.flags%')
			adds_if_not_exists(dst_ip, the_port=port, flag=flag)
		else:
			if verbose == True:
				print "\n[" + Colors.RED + "-" + Colors.RESET + "]" + Colors.RED + "The port " + str(port) + " is closed for " + str(dst_ip) + "\n" + Colors.RESET
		
		sr1(IP(dst=dst_ip)/TCP(sport=RandShort(), dport=port, flags="R"), timeout=2, verbose=False)

def get_host (list_of_part_ips):
	list_of_threads = []
	thread_counter = 0
	max_for_class = 256

	if threads == 1:
		for ip in list_of_threads:
			for i in range(0, max_for_class):
				fullip = str(ip)+str(i)
				get_hosts(fullip)
	else:
		num_for_thread = max_for_class / threads
		num_for_last_thread = max_for_class - (num_for_thread * threads)
		for item in list_of_part_ips:
			for thread_counter in range(1, threads):
				exec("thread%d = myThread(\"get host\", (thread_counter-1)*num_for_thread, thread_counter*num_for_thread, item)" % (thread_counter))
				exec("thread%d.start()" % (thread_counter))
				exec("list_of_threads.append(thread%d)" % (thread_counter))
		
		if num_for_last_thread > 0:
			thread_counter += 1
			exec("thread%d = myThread(\"get host\", max_for_class-num_for_last_thread, max_for_class, item)" % (thread_counter))
			exec("thread%d.start()" % (thread_counter))
			exec("list_of_threads.append(thread%d)" % (thread_counter))

	for t in list_of_threads:
		t.join()
	
class myThread (threading.Thread):
	def __init__(self, func, minimum, maximum, ip=""):
		threading.Thread.__init__(self)
		self.minimum = minimum
		self.maximum = maximum
		self.func = func
		self.ip = ip
	def run(self):
		if (self.func == "get ip"):
			get_ip(self.minimum, self.maximum)
		elif (self.func == "get host"):
			get_hosts(self.ip, self.minimum, self.maximum)
		elif (self.func == "get ports"):
			scan_ports(self.ip, self.minimum, self.maximum)

def get_ip_from_domain(string_domain, dns=""):
	found_domain = False
	try:
		for i in range(0, 11): #to get most of the IPs
			try:
				res = socket.gethostbyname_ex(string_domain)
				found_domain = True
				ips = set(res[2])
				for ip in ips:
					adds_if_not_exists(ip, the_domain=string_domain, dns=dns)
			except:
				pass
			
			try:
				res = socket.getaddrinfo(string_domain, 80)
				found_domain = True
				for ip in res:
					if not ":" in ip:
						adds_if_not_exists(ip[4][0], the_domain=string_domain, dns=dns)
			except:
				pass
			
			try:
				ipofdomain = IP(dst=string_domain)
				found_domain = True
				for ips in ipofdomain:
					adds_if_not_exists(ips.dst, the_domain=string_domain, dns=dns)
			except:
				pass

		if not found_domain:
			if (verbose):
				print "\n[" + Colors.RED + "-" + Colors.RESET + "]" + Colors.RED + " Couldn't get the ip of: " + string_domain + Colors.RESET + "\n"
	
	except Exception:
		if (verbose):
			print "\n[" + Colors.RED + "-" + Colors.RESET + "]" + Colors.RED + " Couldn't get the ip of: " + string_domain + Colors.RESET + "\n"
	
	except KeyboardInterrupt:
		sys.exit(1)	  

def install_tools():
	subprocess.call('reset')
	print Colors.CYAN + "Checking if the needed tools are installed on your OS" + Colors.RESET
	print Colors.BLUE + "Checking for beautifulsoup4 existeness" + Colors.RESET
	subprocess.call('sudo apt-get -y install python-bs4', shell=True)

	print Colors.BLUE + "Checking for scapy existeness" + Colors.RESET
	subprocess.call('sudo apt-get -y install python-scapy', shell=True)

	print Colors.BLUE + "Checking for sqlite3 existeness" + Colors.RESET
	subprocess.call('sudo apt-get -y install sqlite3 libsqlite3-dev', shell=True)

	print Colors.BLUE + "Checking for whois existeness" + Colors.RESET
	subprocess.call('sudo apt-get -y install whois', shell=True)
	subprocess.call('reset')

def restart():
	answer = raw_input("Do you want to restart this program? ")
	if answer.lower().strip() in "y yes".split():
		python = sys.executable
		os.execl(python, python, * sys.argv)

def start():
	
	parser = argparse.ArgumentParser()
	parser.add_argument('-d', '--domain', action='store', metavar='', required=True, dest='domain', help='The domain you want to explore. For ex. google.com')
	parser.add_argument('-w', '--wordlist', action='store', metavar='', required=True, dest='wordlist', help='The Subdomains wordlist')
	parser.add_argument('-t', '--threads', action='store', metavar='', default=3, dest='threads', type=int, help='Number of threads (must be larger than 0. default: 3)')
	parser.add_argument('-v', '--verbose', action='store_true', default=False, dest='verbose', help='Set verbosity')
	parser.add_argument('--version', dest='version', default="2.0", action='version', version='%(prog)s 2.0')

	args = parser.parse_args()

	install_tools()

	print "\n***********************************************************************"
	print "*                      _____                  _____                   *"
	print "* | |_| |__   ___     /  __/ _ __ ___   ___  /  _  /___  _ __         *"
	print "* | __| '_ \ / _ \   |  |   | '__/ _ \ / _ \/  ___/  _ \| '__|        *"
	print "* | |_| | | |  __/   |  |__ | | |  __/|  __/  /   |  __/| |           *"
	print "*  \__|_| |_|\___|    \____||_|  \___| \__/__/     \___||_|           *"
	print "*                                                                     *"
	print "*                                                                     *"
	print "* The CreePer Ver. %s                                                *"  % (args.version)
	print "* Coded by 0xpwn                                                      *"
	print "* bla.doesn\'t-matter@non-of-your-business.cyber                       *"
	print "***********************************************************************\n\n"

	if args.threads < 1:
		parser.print_help()
		print
		sys.exit(1)

	global subslist
	global domain
	global verbose
	global dns
	global threads

	domain = args.domain
	verbose = args.verbose
	threads = args.threads

	start_time = datetime.now()
	print "[" + Colors.MAGENTA + "!" + Colors.RESET + "]" + Colors.MAGENTA + " Started at " + strftime("%H:%M:%S") + "\n" + Colors.RESET

	try:
		subsfile = open(args.wordlist, 'r+a')
	except Exception, e:
		print "Failed to open wordlist.\nError: " + str(e)
		exit()

	subslist = subsfile.readlines()
	found = False

	dns = get_dns(domain)
	get_ip_from_domain(domain, dns)

	from NetcraftAPI import NetcraftAPI
	subdomainsres = NetcraftAPI({'verbose': args.verbose}).search(args.domain)
	
	########## Add the subdomains to the file ##########
	if len(subdomainsres) > 0:
		for s in subdomainsres:
			for line in subslist:
				if s.rstrip('\r\n') == line.rstrip('\r\n'):
					found = True
					break
				else:
					found = False

			if found is False:
				print "adding the subdomain %s to the list" % (s)
				subsfile.write(s.rstrip('\r')+"\n")

		subsfile.close()
	################## End of adding ###################

	# re-opening subsfile to update subslist
	try:
		subsfile = open(args.wordlist, 'r+a')
	except Exception, e:
		print "Failed to open wordlist.\nError: " + str(e)
		exit()

	subslist = subsfile.readlines()
	subsfile.close()

	list_of_threads = []
	with open(args.wordlist) as subsfile:
		number_of_subs = sum(1 for _ in subsfile)
		thread_counter = 0

		if (threads > 1):
			num_of_subs_for_each_thread = number_of_subs / threads
			num_of_subs_for_last_thread = number_of_subs - (num_of_subs_for_each_thread * (threads - 1))

			for thread_counter in range(1, threads):
				exec("thread%d = myThread(func=\"get ip\", minimum=(thread_counter-1)*num_of_subs_for_each_thread, maximum=thread_counter*num_of_subs_for_each_thread)" % (thread_counter))
				exec("thread%d.start()" % (thread_counter))
				exec("list_of_threads.append(thread%d)" % (thread_counter))

			thread_counter += 1
			# last thread handling
			exec("thread%d = myThread(func=\"get ip\", minimum=number_of_subs - num_of_subs_for_last_thread, maximum=number_of_subs)" % (thread_counter))
			exec("thread%d.start()" % (thread_counter))
			exec("list_of_threads.append(thread%d)" % (thread_counter))

		else:
			num_of_subs_for_each_thread = number_of_subs

			for thread_counter in range(1, threads + 1):
				exec("thread%d = myThread(func=\"get ip\", minimum=(thread_counter-1)*num_of_subs_for_each_thread, maximum=thread_counter*num_of_subs_for_each_thread)" % (thread_counter))
				exec("thread%d.start()" % (thread_counter))
				exec("list_of_threads.append(thread%d)" % (thread_counter))

		for t in list_of_threads:
			t.join()

	print "[" + Colors.MAGENTA + "!" + Colors.RESET + "]" + Colors.MAGENTA + " Done resolve ip from subdomains\n" + Colors.RESET

	print "[" + Colors.MAGENTA + "!" + Colors.RESET + "]" + Colors.MAGENTA + " Now gonna try to resolve domains from IPs" + Colors.RESET

	onlypartofip = []
	thepartarr = []
	therealpart = ""
	foundd = False

	for key in sum_dict:
		therealpart = key.rsplit('.', 1)[0] + "."

		if len(onlypartofip) > 0:
			for p in range(0, len(onlypartofip)):
				
				if therealpart == onlypartofip[p]:
					foundd = True
					break
		if not foundd:
			onlypartofip.append(therealpart)

	get_host(onlypartofip)

	print "[" + Colors.MAGENTA + "!" + Colors.RESET + "]" + Colors.MAGENTA + " Now trying to find all open ports for each IP" + Colors.RESET

	for ip in sum_dict:
		start_threads_for_port_scanning(ip)


	#subprocess.call('clear')

################### JSON File ###################
	if not os.path.exists(domain):
		os.makedirs(domain)
	else:
		shutil.rmtree(domain)
		os.makedirs(domain)

	for key in sum_dict:
		sum_dict[key].pop('counter', None)

	with open(domain + "/json.JSON", mode='w') as f:
		json.dump(sum_dict, f, indent=4, sort_keys=True, separators=(',', ': '))
		f.close()

	print json.dump(sum_dict, f, indent=4, sort_keys=True, separators=(',', ': '))
	end_time = datetime.now()
	print "[" + Colors.MAGENTA + "!" + Colors.RESET + "]" + Colors.MAGENTA + " The scan took " + str(end_time - start_time) + "\n" + Colors.RESET
	exit()
	make_DB()

################### SQL ###################
def make_DB():
	import sqlite3, logging

	con = sqlite3.connect(str(domain + "/db.DB"))
	cur = con.cursor()
	try:
		cur.execute("CREATE TABLE full_table(id INT, ip TEXT, domains TEXT, ports TEXT, DNS TEXT)")
	except:
		pass

	counter = 1
	for key in sum_dict:
		cur.execute("INSERT or IGNORE INTO full_table (id, ip) VALUES(?, ?)", (counter, key.encode('utf-8')))

		for k, v in sum_dict[key]['Domains']:
			cur.execute("INSERT or IGNORE INTO full_table (domains) VALUES(?)", (v.encode('utf-8')))

		for port in sum_dict[key]['Ports']:
			cur.execute("INSERT or IGNORE INTO full_table (ports) VALUES(?)", (ports.encode('utf-8')))

		for dns in sum_dict[key]['Dns']:
			cur.execute("INSERT or IGNORE INTO full_table (DNS) VALUES(?)", (dns.encode('utf-8')))
	
	con.commit()
	
	with con:
		cur = con.cursor()
		cur.execute('SELECT * FROM full_table')
		col_names = [cn[0] for cn in cur.description]
		rows = cur.fetchall()

		from prettytable import PrettyTable

		x = PrettyTable(col_names)
		x.align[col_names[1]] = "l"
		x.align[col_names[4]] = "l"
		x.padding_width = 1
		for row in rows:
			x.add_row(row)
		print (x)


if __name__ == "__main__":
	if os.getuid() == 0:
		try:
			start()
		except KeyboardInterrupt:
			print " YA!"
			restart()
	else:
		print ("You must run this as a sudo.")