# The Creeper
Find all subdomains, ip addresses and dns of a domain.

##Installation:
First, git clone the repo to your computer

```git clone https://github.com/0xpwn/The_Creeper.git```

Second, install requirements using pip and your requirements file:

```pip install -r requirements```

Maybe some of you will need to use sudo.

All set, you are ready to go. Run the script as following:

```
usage: main.py [-h] -d  -w  [-t] [-v] [--version]

optional arguments:
  -h, --help        show this help message and exit
  -d , --domain     The domain you want to explore. For ex. google.com
  -w , --wordlist   The Subdomains wordlist
  -t , --threads    Number of threads (must be larger than 0. default: 3)
  -v, --verbose     Set verbosity
  --version         show program's version number and exit
```

For example:
```
sudo python main.py -d youtube.com -w huge -t 7
```



##Legally:
This script has been made for legal use and for fun. Everything you are about to do with this tool, is on your responsebility.

