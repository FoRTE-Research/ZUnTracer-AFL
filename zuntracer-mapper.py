#!/usr/bin/python3

import sys
from capstone import *

usage = "\n\tUsage: " \
		"\tzuntracer-mapper.py [/path/to/oracle/zipr/dir] [/path/to/tracer/zipr/dir] [/path/to/outmap], [/path/to/maplog]\n"

if len(sys.argv) < 5:
	print ("Missing argument(s)!")
	print (usage)

oracleZiprDir = sys.argv[1]
tracerZiprDir = sys.argv[2]
outMapPath 	  = sys.argv[3]
outLogPath 	  = sys.argv[4]
offset        = "0x400000"

addrMap = []
bbidMap = []
oracleCedgeLst = []
tracerCedgeLst = []

# Stores mapping of instruction ID's to oracle instruction addresses

def load_addr_map():
	with open ("%s/zipr.map" % oracleZiprDir) as oracleZipr:
		lines = oracleZipr.readlines()[1:]
		
		for line in lines:
			line = line.split()
			insn = int(line[0], 16) 
			addr = line[3] 
			addrMap.append((insn, addr))	

	return


# Stores mapping of instruction ID's to tracer bitmap ID's

def load_bbid_map():
	with open("%s/zax.map" % tracerZiprDir) as tracerZax:
		lines = tracerZax.readlines()[1:]

		for line in lines:
			line = line.split()
			bbid = int(line[0], 16) 
			insn = int(line[1].split(':')[0], 16) 
			bbidMap.append((insn, bbid))

	return


# Loads both oracle and tracer critical edge maps

def load_cedge_lsts():
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


# Helper function to return disassembled bytes

def get_disasm_bytes(dump, addr):
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.syntax = CS_OPT_SYNTAX_ATT
	md.detail = True
	return list(md.disasm(dump, int(addr, 16)))[0]


# Retrieves the matching trace bitmap ID given an instruction ID

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


# Retrieves the matching trace bitmap ID given an instruction ID

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


# Attempt to find match for (bbid,insn) to (addr,insn) pairs

def map_regular_blocks(outMapFile, outLogFile):
	for block in bbidMap:
		insn = block[0]
		bbid = block[1]
		addr = get_oracle_addr_from_insn(insn, outLogFile)
		
		if addr != -1:
			addr = int(addr, 16) - int(offset, 16)
			outMapFile.write("%i, %i, %i, 1, 0xCC\n" % (bbid, addr, addr))	

	return


def get_tracer_bbid_from_cedge(insnSrc, broken, etype, log):
	matches = [i for i, cedg in enumerate(tracerCedgeLst) 
		if  cedg[0] == insnSrc and
			#cedg[1] == broken and
			cedg[2] == etype]

	if len(matches) == 0:
		log.write("ERROR: no cedge matches found for cedge (%s,%s,%s)" % (insnSrc, broken, etype))
		return -1

	if len(matches) > 1:
		log.write("ERROR: multiple cedge matches found for cedge (%s,%s,%s)" % (insnSrc, broken, etype))
		return -1

	insnDst = tracerCedgeLst[matches[0]][3]
	bbid = get_tracer_bbid_from_insn(insnDst, log)

	return bbid


def map_cedge_fallthru(outMapFile, outLogFile):
	for cedge in oracleCedgeLst:
		insnSrc = cedge[0]
		broken 	= cedge[1]
		etype 	= cedge[2]
		insnDst = cedge[3]

		if (broken == "true"):

			bbid = get_tracer_bbid_from_cedge(insnSrc, broken, etype, outLogFile)
			addr = get_oracle_addr_from_insn(insnDst, outLogFile)

			if (bbid != -1):
				addr = int(addr, 16) - int(offset, 16)
				outMapFile.write("%i, %i, %i, 1, 0xCC\n" % (bbid, addr, addr))

	return

def main():
	outMapFile = open(outMapPath, "w+")
	outLogFile = open(outLogPath, "w+")

	outMapFile.write("# BLOCK_ID, INSN_ADDR, ADJST_ADDR, MOD_LEN, MOD_BYTES\n")

	load_addr_map()
	load_bbid_map()
	load_cedge_lsts()

	map_regular_blocks(outMapFile, outLogFile)
	map_cedge_fallthru(outMapFile, outLogFile)

	outMapFile.close()
	outLogFile.close()

if __name__ == "__main__":
	main()

