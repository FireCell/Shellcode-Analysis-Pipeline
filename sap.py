#!/usr/bin/env python

# TODO
# 1. get shellcode from 
#	1a. shellstorm
#	1b. exploitdb
#	1c. msf
# 2. create .bin files for these shellcodes
# 3. create .pcap files for these shellcodes
# 4. test shellcode with libemu


import os
import sys
import time
import datetime
import argparse
import pylibemu
from ConfigParser import SafeConfigParser


banner = 'sap.py - Shellcode Analysis Pipleline'
verstring = '0.1'
author = 'Ankur Tyagi (7h3rAm)'

globs = {
	'debug': False,

	'config': None,
	'search': None,

	'pgtpath': None,

	'shellstormpath': None,

	'doshellstorm': False,
	'doexploitdb': False,
	'dometasploit': False,
	'doall': False,

	'binfileslist': [],
	'genpcaps': False,
	'emuprofilesize': 0
}


def getcurtime():
    return datetime.datetime.now()


def gettimestamp():
    return "%s %s" % (datetime.datetime.now().strftime("%d-%b-%Y %H:%M:%S.%f"), time.tzname[0])


def doprint(msg, level='NORM', back=0, newline=True):
    frame = sys._getframe(back + 1)
    filename = os.path.basename(frame.f_code.co_filename)
    lineno = frame.f_lineno
    funcname = frame.f_code.co_name
    print "[%s] [%s] %s: %s" % (gettimestamp(), funcname, level, msg)


def donorm(msg):
    doprint(msg, '[NORM]', back=1)


def dodebug(msg):
    doprint(msg, '[DEBUG]', back=1)


def dowarn(msg):
    doprint(msg, '[WARN]', back=1)


def doerror(msg):
    doprint(msg, '[ERROR]', back=1)


def bin2pcap():
	donorm('Found %d binfiles for pcap generation' % (len(globs['binfileslist'])))

	for count, filename in enumerate(globs['binfileslist']):
		pgtcli = '%s %s >/dev/null 2>&1' % (globs['pgtpath'], filename)

		os.popen(pgtcli).read()
		donorm('(%03d/%03d) Generating pcaps for %s' % (count+1, len(globs['binfileslist']), filename))

		os.popen('mv ./output/%s/HTTP_GET_raw_raw.pcap ./%s-HTTP_GET_raw_raw.pcap' % (filename, filename))
		os.popen('mv ./output/%s/HTTP_POST_raw_raw.pcap ./%s-HTTP_POST_raw_raw.pcap' % (filename, filename))
		os.popen('mv ./output/%s/TCP_CTS_raw.pcap ./%s-TCP_CTS_raw.pcap' % (filename, filename))
		os.popen('mv ./output/%s/TCP_STC_raw.pcap ./%s-TCP_STC_raw.pcap' % (filename, filename))

	os.popen('rm -rf ./output/')


def dometasploit():
	pass

def doexploitdb():
	pass


def doshellstorm():
	"""http://repo.shell-storm.org/shellcode/"""

	shellstormsearchcli = '%s -search \'%s\' | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" | grep -oP "\[\d+\]" | grep -oP "\d+"' % (globs['shellstormpath'], globs['search'])

	scids = []
	for item in os.popen(shellstormsearchcli).read().strip().split('\n'):
		if int(item) not in scids: scids.append(int(item))

	donorm('Found %d shellcode ids @ shell-storm with search-string: \'%s\'' % (len(scids), globs['search']))

	for count, id in enumerate(scids):
		scidfile = './%d.bin' % (id)
		shellstormdisplaycli = r'echo $(%s -display %d | pcregrep -oM "char \w+\[\][^;]+" | pcregrep -oM "([\x5c]x[a-fA-F0-9]{2})+")' % (globs['shellstormpath'], id)

		sc = os.popen(shellstormdisplaycli).read().strip().replace('\\x', '').replace(' ', '').decode('hex')

		if len(sc) > 0:
			fo = open(scidfile, 'w')
			fo.write(sc)
			fo.close()
			donorm('(%03d/%03d) Wrote %dB from shellcode id#%d into %s' % (count+1, len(scids), len(sc), id, scidfile))
			if scidfile not in globs['binfileslist']:
				globs['binfileslist'].append(scidfile)

		else:
			donorm('(%03d/%03d) Skipped shellcode id#%d as only %dB found!' % (count+1, len(scids), id, len(sc)))


def emutest():
	emu = pylibemu.Emulator(globs['emuprofilesize'])

	for count, filename in enumerate(globs['binfileslist']):
		fo = open(filename, 'r')
		data = fo.read()
		fo.close()
		offset = emu.shellcode_getpc_test(data)
		if offset >= 0:
			emu.prepare(data, offset)
			emu.test()

			if emu.emu_profile_output:
				print emu.emu_profile_output

			donorm('(%03d/%03d) Testing shellcode file: %s with Libemu: offset = %d' % (count+1, len(globs['binfileslist']), filename, offset))


def main():
	starttime = getcurtime()

	print '%s (v%s)' % (banner, verstring)
	print '%s' % (author)
	print

	donorm('Session started @ %s' % (starttime))

	parser = argparse.ArgumentParser(
		description = banner,
		version = verstring,
		epilog = 'EXAMPLE: %(prog)s -s windows')

	parser.add_argument('-s', '--search', action='store', dest='search', help='shellcode search')
	parser.add_argument('-c', '--config', action='store', dest='config', help='config file - default: sap.cnf')
	parser.add_argument('-d', '--debug', action='store_true', dest='debug', default=False, help='enable debug output')

	parser.add_argument('-S', '--shellstorm', action='store_true', dest='shellstorm', default=False, help='shellstorm lookup')
	parser.add_argument('-E', '--exploitdb', action='store_true', dest='exploitdb', default=False, help='exploitdb lookup')
	parser.add_argument('-M', '--metasploit', action='store_true', dest='metasploit', default=False, help='metasploit lookup')

	parser.add_argument('-p', '--genpcaps', action='store_true', dest='genpcaps', default=False, help='generate pcaps')

	args = parser.parse_args()
	config = SafeConfigParser()

	if args.debug:
		globs['debug'] = True

	if args.config:
		globs['config'] = args.config
	else:
		globs['config'] = './sap.cnf'

	if globs['debug']:
		dodebug('Using %s as configuration file' % (globs['config']))

	config.read(globs['config'])

	if args.search:
		globs['search'] = args.search
	else:
		if not config.has_section('defaults'):
			doerror('Config file is missing mandatory section \'defaults\'! Cannot proceed further.')
			sys.exit(1)
		elif not config.has_option('defaults', 'search'):
			doerror('Config file is missing mandatory option \'search\'! Cannot proceed further.')
			sys.exit(1)
		else:
			globs['search'] = config.get('defaults', 'search')

	if globs['debug']:
		dodebug('Using \'%s\' as search string' % (globs['search']))

	if config.has_option('defaults', 'pgtpath'):
		globs['pgtpath'] = config.get('defaults', 'pgtpath')

	if args.shellstorm:
		globs['doshellstorm'] = True

	if args.exploitdb:
		globs['doexploitdb'] = True

	if args.metasploit:
		globs['dometasploit'] = True

	if not globs['doshellstorm'] and not globs['doexploitdb'] and not globs['dometasploit']:
		globs['doall'] = True
		if globs['debug']:
			dodebug('Enabled all shellcode soruces: shellstorm/exploitdb/metasploit')

	if globs['doall'] or globs['doshellstorm']:
		if config.has_option('defaults', 'shellstormpath'):
			globs['shellstormpath'] = config.get('defaults', 'shellstormpath')
			doshellstorm()

	if globs['doall'] or globs['doexploitdb']:
		if config.has_option('defaults', 'exploitdbpath'):
			globs['exploitdbpath'] = config.get('defaults', 'exploitdbpath')
			doexploitdb()

	if globs['doall'] or globs['dometasploit']:
		if config.has_option('defaults', 'metasploitpath'):
			globs['metasploitpath'] = config.get('defaults', 'metasploitpath')
			dometasploit()

	if args.genpcaps:
		globs['genpcaps'] = True

	if len(globs['binfileslist']) > 0 and globs['genpcaps']:
		if globs['debug']:
			dodebug('Initiating pcap generation for downloaded shellcode')

		bin2pcap()

	if config.has_option('defaults', 'emuprofilesize'):
		globs['emuprofilesize'] = config.getint('defaults', 'emuprofilesize')	

	if len(globs['binfileslist']) > 0:
		if globs['debug']:
			dodebug('Initiating Libemu testing for downloaded shellcode')

		emutest()

	endtime = getcurtime()
	donorm('Session completed in %s' % (endtime-starttime))
	print


if __name__ == '__main__':
	main()
