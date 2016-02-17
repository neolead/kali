import nmap, os

nm = nmap.PortScanner()
nm.scan(hosts = '192.168.1.110-116', arguments = '-PU -sn')
for host in nm.all_hosts():
    print "host: %s" % host
print "FIRST"
hostlist = ' '.join(nm.all_hosts())
nm.scan(hosts = hostlist, arguments = '-PU -sn')

for host in nm.all_hosts():
    print "host: %s" % host

#调用外部程序
os.system('./runsnmp')
