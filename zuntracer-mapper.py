#!/usr/bin/python3

import sys
from capstone import *

#------------------------------------------------------------
oracleZiprDir 	= ""		 # Path to oracle zipr dir
tracerZiprDir 	= ""		 # Path to tracer zipr dir
outMapPath 	  	= ""		 # Path to output mapping
outLogPath 	  	= "" 		 # Path to mapper error log
offset        	= "0x400000" # Set for PIE/non-PIE bins
addrMap 	  	= []		 # (insn, oracle addr) map
bbidMap			= []	 	 # (insn, tracer bitmap ID) map
oracleCedgeLst 	= []		 # Oracle binary ceb.map
tracerCedgeLst 	= []		 # Tracer binary ceb.map
#------------------------------------------------------------

# Stores mapping of instruction ID's to oracle addresses.

def load_addr_map(oracleZiprDir):
	with open ("%s/zipr.map" % oracleZiprDir) as oracleZipr:
		lines = oracleZipr.readlines()[1:]
		
		for line in lines:
			line = line.split()
			insn = int(line[0], 16) 
			addr = line[3] 
			addrMap.append((insn, addr))	

	return


# Stores mapping of instruction ID's to tracer bitmap ID's.

def load_bbid_map(tracerZiprDir):
	with open("%s/zax.map" % tracerZiprDir) as tracerZax:
		lines = tracerZax.readlines()[1:]

		for line in lines:
			line = line.split()
			bbid = int(line[0], 16) 
			insn = int(line[1].split(':')[0], 16) 
			bbidMap.append((insn, bbid))

	return


# Stores both oracle and tracer critical edge lists.

def load_cedge_lsts(oracleZiprDir, tracerZiprDir):
	oracleCebFile = open("%s/ceb.map" % oracleZiprDir, "r")
	tracerCebFile = open("%s/ceb.map" % tracerZiprDir, "r")
	
	for line in oracleCebFile.readlines()[1:]:
		line = line.split()
		insnSrc = int(line[0], 16)
		broken 	= line[1]
		etype 	= line[2]
		insnDst = int(line[3], 16)
		oracleCedgeLst.append((insnSrc, broken, etype, insnDst))

	for line in tracerCebFile.readlines()[1:]:
		line = line.split()
		insnSrc = int(line[0], 16)
		broken 	= line[1]
		etype 	= line[2]
		insnDst = int(line[3], 16)
		tracerCedgeLst.append((insnSrc, broken, etype, insnDst))

	oracleCebFile.close()
	tracerCebFile.close()
	
	return


# Given a byte dump, return its disassembled instruction.

def get_disasm_bytes(dump, addr):
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.syntax = CS_OPT_SYNTAX_ATT
	md.detail = True
	return list(md.disasm(dump, int(addr, 16)))[0]


# Given an instruction ID, retreives its tracer bitmap ID.

def get_tracer_bbid_from_insn(insn, log):
	matches = [i for i, pair in enumerate(bbidMap) if pair[0] == insn]

	if len(matches) == 0:
		log.write("ERROR: no bbid matches found for insn %s" % insn)
		return -1

	if len(matches) > 1:
		log.write("ERROR: multiple bbid matches found for insn %s" % insn)
		return -1

	bbid = bbidMap[matches[0]][1]
	log.write("Found bbid match for insn %s" % insn)

	return bbid


# Given an instruction ID, retreives its oracle instruction address.

def get_oracle_addr_from_insn(insn, log):
	matches = [i for i, pair in enumerate(addrMap) if pair[0] == insn]

	if len(matches) == 0:
		log.write("ERROR: no addr matches found for insn %s" % insn)
		return -1

	if len(matches) > 1:
		log.write("ERROR: multiple addr matches found for insn %s" % insn)
		return -1

	addr = addrMap[matches[0]][1]
	log.write("Found addr match for insn %s" % insn)

	return addr


# Retrieve the identical critical edge from tracer given an oracle cedge.

def get_tracer_bbid_from_cedge(insnSrc, broken, etype, log):
	matches = [i for i, cedg in enumerate(tracerCedgeLst) 
		if  cedg[0] == insnSrc and
			cedg[2] == etype]

	if len(matches) == 0:
		log.write("ERROR: no cedge matches found for cedge (%s,%s,%s)" % (insnSrc, etype))
		return -1

	if len(matches) > 1:
		log.write("ERROR: multiple cedge matches found for cedge (%s,%s,%s)" % (insnSrc, etype))
		return -1

	insnDst = tracerCedgeLst[matches[0]][3]
	bbid = get_tracer_bbid_from_insn(insnDst, log)

	return bbid


# Map regular (i.e., interrupt-only) basic blocks.
# Matches (insn, bbid) to (insn, addr) pairs by insn.

def map_regular_blocks(outMapFile, outLogFile):
	for block in bbidMap:
		insn = block[0]
		bbid = block[1]
		addr = get_oracle_addr_from_insn(insn, outLogFile)

		if addr != -1:
			addr = int(addr, 16) - int(offset, 16)
			outMapFile.write("%i, %i, %i, 1, 0xCC\n" % (bbid, addr, addr))	

	return

# Map critical edge-splitting blocks to oracle addresses. 
# Matches oracle's cedge to tracer's based on source insn
# and the critical edge's type (i.e., "fall" or "targ"),
# then retrieves oracle addr from source instruction.

def map_cedge_split(outMapFile, outLogFile):
	for cedge in oracleCedgeLst:
		insnSrc = cedge[0]
		broken 	= cedge[1]
		etype 	= cedge[2]
		insnDst = cedge[3]

		if (broken == "true"): # Denotes the edge was split with new block.

			bbid = get_tracer_bbid_from_cedge(insnSrc, broken, etype, outLogFile)
			addr = get_oracle_addr_from_insn(insnDst, outLogFile)

			if (bbid != -1):
				addr = int(addr, 16) - int(offset, 16)
				outMapFile.write("%i, %i, %i, 1, 0xCC\n" % (bbid, addr, addr))

	return

# Main body

def main():
	usage = "\n\tUsage: " \
		"\tzuntracer-mapper.py [/path/to/oracle/zipr/dir] [/path/to/tracer/zipr/dir] [/path/to/outmap], [/path/to/maplog]\n"

	if len(sys.argv) < 5:
		print ("Missing argument(s)!")
		print (usage)
		exit(1)

	oracleZiprDir = sys.argv[1]
	tracerZiprDir = sys.argv[2]	
	outMapPath	  = sys.argv[3]
	outLogPath 	  = sys.argv[4]

	outMapFile = open(outMapPath, "w+")
	outLogFile = open(outLogPath, "w+")

	outMapFile.write("# BLOCK_ID, INSN_ADDR, ADJST_ADDR, MOD_LEN, MOD_BYTES\n")

	load_addr_map(oracleZiprDir)
	load_bbid_map(tracerZiprDir)
	load_cedge_lsts(oracleZiprDir, tracerZiprDir)

	map_regular_blocks(outMapFile, outLogFile)
	map_cedge_split(outMapFile, outLogFile)

	outMapFile.close()
	outLogFile.close()

if __name__ == "__main__":
	main()

