#!/usr/bin/python3

import sys

usage = "\n\tUsage: " \
		"\tbuild-map.py [/path/to/oracle/zipr.map] [/path/to/tracer/zax.map] [/path/to/outmap], [/path/to/maplog]\n"

if len(sys.argv) < 5:
	print ("Missing argument(s)!")
	print (usage)

oracleZiprPath = sys.argv[1]
tracerZaxPath  = sys.argv[2]
outMapPath     = sys.argv[3]
mapLogPath	   = sys.argv[4]
offset         = "0x400000"

oracleMap = []
with open(outMapPath, "w+") as outMap:

	# Zipr.map: maps instructions to addresses
	with open (oracleZiprPath) as oracleZipr:
		
		lines = oracleZipr.readlines()[1:]
		for line in lines:
			line = line.split()

			# Merge disas all into one col (unused as of now)
			line[5] = " ".join(line[5:])	
			line = line[:6]
			
			# Store pairing of instruction ID, new address
			insnID = int("0x%s" % line[0], 16)
			newAddr = line[3]
			oracleMap.append((insnID, newAddr))

	# Zax.map: maps basic blocks to instructions
	with open(tracerZaxPath) as tracerZax:
		
		lines = tracerZax.readlines()[1:]
		for line in lines:
			line = line.split()
			bbID = int(line[0],10)
			insnID = int(line[1].split(':')[0], 16)

			found=0
			for pair in oracleMap:

				# Attempt to match Zax(bbID, insID) to Zipr(insID, newAddr)
				if insnID == pair[0]:
					
					# Compute offset adjusted address and write to map
					newAddr = int(pair[1],16) - int(offset,16)
					outMap.write("%i,%i\n" % (newAddr, int(bbID)))
					found=1

			# Write to logfile
			with open(mapLogPath, "w+") as mapLog:

				if not found:
					mapLog.write("Cannot find mapping for insn: %s" % hex(insnID))
				else:
					mapLog.write("Found mapping for insn: %s" % hex(insnID))


