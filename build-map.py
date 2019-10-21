#!/usr/bin/python3

import sys

usage = "\n\tUsage: " \
		"\tbuild-map.py [/path/to/oracle/zipr/dir] [/path/to/tracer/zipr/dir] [/path/to/outmap], [/path/to/maplog]\n"

if len(sys.argv) < 5:
	print ("Missing argument(s)!")
	print (usage)

oracleZiprDir = sys.argv[1]
tracerZiprDir = sys.argv[2]
outMapPath    = sys.argv[3]
mapLogPath	  = sys.argv[4]
offset        = "0x400000"

# Zipr.map : maps instructions to addresses
def load_addr_map():
	addrMap = []

	with open ("%s/zipr.map" % oracleZiprDir) as oracleZipr:
		lines = oracleZipr.readlines()[1:]
		
		for line in lines:
			line = line.split()

			# Merge disas all into one col (unused as of now)
			line[5] = " ".join(line[5:])	
			line = line[:6]
			
			# Store pairing of instruction ID, new address
			insn = int(line[0], 16) # base-16
			addr = line[3] 
			addrMap.append((addr, insn))	

	return addrMap

# Zax.map : maps basic blocks to instructions
def load_bbid_map():
	bbidMap = []

	with open("%s/zax.map" % tracerZiprDir) as tracerZax:
		lines = tracerZax.readlines()[1:]

		for line in lines:
			line = line.split()
			bbid = int(line[0], 16) 
			insn = int(line[1].split(':')[0], 16) 
			bbidMap.append((bbid, insn))

	return bbidMap

# Ceb.map : maps critical edges to their insns, types
def load_cedg_lst():
	cedgLst = []

	with open("%s/ceb.map" % tracerZiprDir) as tracerCeb:
		lines = tracerCeb.readlines()[1:]

		for line in lines:
			line = line.split()
			insnOld   = int(line[0], 16) 
			insnNew   = int(line[3], 16)
			broken 	  = line[1]
			etype     = line[2]

			if (etype == 'targ'):
				cedgLst.append((insnOld, insnNew))

	return cedgLst


def main():
	outMap = open(outMapPath, "w+")
	mapLog = open(mapLogPath, "w+")

	bbidMap = load_bbid_map()
	addrMap = load_addr_map()
	#cedgLst = load_cedg_lst()
	cedgLst = []


	# Attempt to match all cedge insn's to bbid's and addresses
	for pair in cedgLst:
		insnOld = pair[0]
		insnNew = pair[1]

		# Build (insnOld, bbid) map by matching insnNew to the block starting with it
		matches = [i for i, bbidPair in enumerate(bbidMap) if bbidPair[1] == insnNew]
		if len(matches) == 1:
			indx = matches[0]
			bbid = bbidMap[indx][0]
			bbidMap.append((bbid, insnOld))
			#print (insnOld, bbid)

		# Build (addrNew, bbid) map
		# 

	# Attempt to find match for (bbid,insn) to (addr,insn) pairs
	for pair in bbidMap:
		bbid = pair[0]
		insn = pair[1]

		matches = [i for i, addrPair in enumerate(addrMap) if addrPair[1] == insn]

		# If found match write out the (addr,bbid) tuple
		if len(matches) == 1:
			indx = matches[0]
			addr = addrMap[indx][0]
			addr = int(addr, 16) - int(offset,16)
			outMap.write("%i,%i,CC\n" % (addr, bbid))
			mapLog.write("Found mapping for insn: %s\n" % hex(insn))

		# Multiple matches would indicate something wrong on the zipr-side
		elif len(matches) > 1:
			mapLog.write("Multiple mappings found for insn: %s\n" % hex(insn))

		# Log unmapped insns
		else:
			mapLog.write("Cannot find mapping for insn: %s\n" % hex(insn))

	outMap.close()
	mapLog.close()


if __name__ == "__main__":
	main()

