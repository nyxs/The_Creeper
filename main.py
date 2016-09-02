import os
import sys
import json
import logging
import subprocess
import threading
import argparse
import shlex
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

subsandip_arr = []
subsandip_dict = {}
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

def adds_if_not_exists(the_domain, the_ip, the_port, module, dns):
    the_domain = str(the_domain)
    the_ip = str(the_ip)
    the_port = str(the_port)
    module = str(module)
    dns = str(dns)
    founditem = False
    if len(subsandip_arr) > 0:
        for k in range(0, len(subsandip_arr), 4):
            if the_domain == subsandip_arr[k] and the_ip == subsandip_arr[k+1]:
                print "\n" + the_domain + " with ip " + the_ip + " is already exists"
                founditem = True
                break
            else:
                founditem = False

        if founditem == False:
            subsandip_dict[the_domain] = the_ip
            subsandip_arr.append(the_domain)
            subsandip_arr.append(the_ip)
            subsandip_arr.append(the_port)
            subsandip_arr.append("")
            subsandip_arr.append(dns)
            print "[" + Colors.GREEN + "+" + Colors.RESET + "]" + Colors.GREEN + " The domain: " + the_domain + " with the ip " + the_ip + " added\n" + Colors.RESET #using " + module + " module" + Colors.RESET + "\n"
    else:
        subsandip_dict[the_domain] = the_ip
        subsandip_arr.append(the_domain)
        subsandip_arr.append(the_ip)
        subsandip_arr.append(the_port)
        subsandip_arr.append("")
        subsandip_arr.append(dns)
        print "[" + Colors.GREEN + "+" + Colors.RESET + "]" + Colors.GREEN + " The domain: " + the_domain + " with the ip " + the_ip + " added\n" + Colors.RESET #using " + module + " module" + Colors.RESET + "\n"

def get_dns(address):
	proc1 = subprocess.Popen(shlex.split('whois ' + address),stdout=subprocess.PIPE)
	proc2 = subprocess.Popen(shlex.split('grep "Name Server"'),stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc3 = subprocess.Popen(shlex.split('grep -v "   N"'),stdin=proc2.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	proc1.stdout.close()
	proc2.stdout.close()
	out,err=proc3.communicate()
	return ('{0}'.format(out.replace("\n", ", ").replace("Name Server: ", ""))[:-2])

def get_ip (thread_name, minimum, maximum):
	for line in range(minimum, maximum):
		#print "\nnow trying: " + subslist[line].strip() + '.' + domain + " (" + thread_name + ")"
		get_ip_from_domain(subslist[line].strip() + '.' + domain)

def get_those_shitty_ips(current_ip):
    #from scapy.all import *
    iparr = str(current_ip).split('.')
    iparr2 = ""
    module = "Scapy: Resolve DNS"
    for i in reversed(iparr):
        iparr2 += i + "."
    iparr2 += "in-addr.arpa"
    ans2 = sr1(IP(dst="8.8.8.8", ttl=10)/UDP()/DNS(rd=1, qd=DNSQR(qname=iparr2, qtype='PTR')), timeout=2, verbose=False)

    counter = 0
    while True:
        try:
            if '.' in str(ans2[DNS].ar[counter].rrname):
                newrrname = str(ans2[DNS].ar[counter].rrname)[:-1]
                print newrrname + ": " + ans2[DNS].ar[counter].rdata
                counter += 1
                adds_if_not_exists(newrrname, str(ans2[DNS].ar[counter].rdata), "", module, dns)
            else:
                pass
        except:
            break
        
def get_host (thread_name, everyitem):
    for endofip in range(0, 255):
        fullip = everyitem + str(endofip)
        print
        #print "address number " + str(counting) + " out of " + str(len(onlypartofip) * 255)
        print thread_name + " is trying: " + fullip
        get_those_shitty_ips(str(fullip))
    
class myThread (threading.Thread):
    def __init__(self, what_to_do, threadID, name, minimum, maximum):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.minimum = minimum
        self.maximum = maximum
        self.todo = what_to_do
    def run(self):
        #print "Starting " + self.name
        if (self.todo == "get ip"):
            get_ip(self.name, self.minimum, self.maximum)
        elif (self.todo == "get host"):
            get_host(self.name, self.minimum)

def get_ip_from_domain(string_domain, dns=""):
    try:
        try:
            ipofdomain = IP(dst=string_domain)
            module = "Scapy: IP by domain"
            for ips in ipofdomain:
                adds_if_not_exists(string_domain, ips.dst, "", module, dns)
        except Exception as e:
        	template = "An exception of type {0} occured. Arguments:\n{1!r}"
        	message = template.format(type(e).__name__, e.args)
        	if not "gaierror" in message:
        		print message
        	else:
        		if (verbose):
        			print "\n[" + Colors.RED + "-" + Colors.RESET + "]" + Colors.RED + " Scapy could not get the ip of: " + string_domain + Colors.RESET + "\n"
    except KeyboardInterrupt:
        exit()      

def installshit():
    subprocess.call('clear')
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
	installshit()

	from NetcraftAPI import NetcraftAPI

	parser = argparse.ArgumentParser()
	parser.add_argument('-d', '--domain', action='store', required=True, dest='domain', help='The domain you want to explore. For ex. google.com')
	parser.add_argument('-w', '--wordlist', action='store', required=True, dest='wordlist', help='The Subdomains wordlist')
	parser.add_argument('-t', '--threads', action='store', default=3, dest='threads', type=int, help='Number of threads (default: 3)')
	parser.add_argument('-v', '--verbose', action='store_true', default=False, dest='verbose', help='Set verbosity')
	parser.add_argument('--version', dest='version', default="2.0", action='version', version='%(prog)s 2.0')

	args = parser.parse_args()

	print "\n***********************************************************************"
	print "*                      _____                  _____                   *"
	print "* | |_| |__   ___     /  __/ _ __ ___   ___  /  _  /___  _ __         *"
	print "* | __| '_ \ / _ \   |  |   | '__/ _ \ / _ \/  ___/  _ \| '__|        *"
	print "* | |_| | | |  __/   |  |__ | | |  __/|  __/  /   |  __/| |           *"
	print "*  \__|_| |_|\___|    \____||_|  \___| \__/__/     \___||_|           *"
	print "*                                                                     *"
	print "*                                                                     *"
	print "* The CreePer Ver. %s                                                *"  % (args.version)
	print "* Coded by fr13nd                                                     *"
	print "* bla.doesn\'t-matter@non-of-your-business.cyber                       *"
	print "***********************************************************************\n\n"


	global subslist
	global domain
	global verbose
	global dns

	domain = args.domain
	verbose = args.verbose
	try:
		subsfile = open(args.wordlist, 'r+a')
	except Exception, e:
		print "Failed to open wordlist.\nError: " + str(e)
		exit()

	subslist = subsfile.readlines()
	found = False

	dns = get_dns(domain)
	get_ip_from_domain(domain, dns)

	subdomainsres = NetcraftAPI({'verbose': args.verbose}).search(args.domain)
    
	########## Add the subdomains to the file ##########
	for s in subdomainsres:
	    for line in subslist:
	        if s.rstrip('\r\n') == line.rstrip('\r\n'):
	            found = True
	            break
	        else:
	            found = False

	    if found is False:
	        print "adding " + s
	        subsfile.write(s.rstrip('\r')+"\n")
	subsfile.close()
	################## End of adding ###################

	threads = []
	with open(args.wordlist) as subsfile:
	    number_of_subs = sum(1 for _ in subsfile)
	    #subslist = subsfile.readlines()
	    thread_counter = 0

	    num_of_subs_for_each_thread = number_of_subs / args.threads
	    num_of_subs_for_last_thread = number_of_subs - (num_of_subs_for_each_thread * (args.threads - 1))

	    for thread_counter in range(1, args.threads):
	    		exec("thread%d = myThread(\"get ip\", thread_counter, \"Thread-\" + str(thread_counter), (thread_counter-1)*num_of_subs_for_each_thread, thread_counter*num_of_subs_for_each_thread)" % (thread_counter))
	    		exec("thread%d.start()" % (thread_counter))
	    		exec("threads.append(thread%d)" % (thread_counter))

	    thread_counter += 1
    	# last thread handling
    	exec("thread%d = myThread(\"get ip\", thread_counter, \"Thread-\" + str(thread_counter), number_of_subs - num_of_subs_for_last_thread, number_of_subs)" % (thread_counter))
    	exec("thread%d.start()" % (thread_counter))
    	exec("threads.append(thread%d)" % (thread_counter))

    	for t in threads:
    		t.join()

	onlypartofip = []
	thepartarr = []
	therealpart = ""
	threads = []

	for integer in range(1, len(subsandip_arr), 4):
		thepartarr = str(subsandip_arr[integer]).split('.')
		for p in range(0, len(thepartarr) - 1):
			therealpart += thepartarr[p] + "."

		if len(onlypartofip) > 0:
			for p2 in range(0, len(onlypartofip)):
				foundd = False
				if therealpart == onlypartofip[p2]:
					foundd = True
					break
				else:
					foundd = False

			if foundd is False:
				onlypartofip.append(therealpart)
		else:
			onlypartofip.append(therealpart)

		therealpart = ""

	counting = 1
	for everyitem in range(0, len(onlypartofip)):
	    exec("thread%d = myThread(\"get host\", everyitem + 1, \"Thread-\" + str(everyitem + 1), onlypartofip[everyitem], \"\")" % (everyitem + 1))
	    exec("thread%d.start()" % (everyitem + 1))
	    exec("threads.append(thread%d)" % (everyitem + 1))

	for t in threads:
	    t.join()

	subprocess.call('clear')

################### JSON File ###################
	if not os.path.exists(domain):
		os.makedirs(domain)

	with open(domain + "/json.JSON", mode='w') as f:
		json.dump(subsandip_dict, f, indent=4, sort_keys=True, separators=(',', ': '))
		f.close()

	make_DB()

################### SQL ###################
def make_DB():
    import sqlite3, logging

    con = sqlite3.connect(str(domain + "/db.DB"))
    cur = con.cursor()
    try:
        cur.execute("CREATE TABLE hosts_ips_ports(id INT, Subdomains TEXT, ip TEXT, port TEXT, Module TEXT, DNS TEXT)")
    except:
        pass

    counter = 0
    for i in range(0, len(subsandip_arr), 5):
        counter += 1
        cur.execute("INSERT or IGNORE INTO hosts_ips_ports VALUES(?, ?, ?, ?, ?, ?)", (counter, subsandip_arr[i].encode('utf-8'),
                                                                          subsandip_arr[i+1].encode('utf-8'),
                                                                          subsandip_arr[i+2].encode('utf-8'),
                                                                          subsandip_arr[i+3].encode('utf-8'),
                                                                          subsandip_arr[i+4].encode('utf-8')))
        con.commit()

    with con:
        cur = con.cursor()
        cur.execute('SELECT * FROM hosts_ips_ports')
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
	    print ("You must run this as a sudoer.")