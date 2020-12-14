the program runs on the linux platform

install snmp and snmp.d and snmp-mibs-downloader
	if your OS are ubuntu:
	you can do the following order
	'sudo apt install snmp'
	'sudo apt install snmpd'
	'sudo apt install snmp-mibs-downloader'

configure the snmp.conf:
	turn 'mibs : ' into '#mibs :'

configure the snmpd.conf:
	add 'view   systemonly  included   .1' under 'view   systemonly  included   .1.3.6.1.2.1.25.1'

restart snmpd
	'service snmpd restart'

run ./scanner
