#!/usr/bin/python3

import os
import socket
import argparse
import readline
import subprocess

from pwn import *

class POPPER:
	def __init__(self, args):
		self.args = args
		self.log = log.progress('')

	def connect(self):
		io = remote(self.args.target, self.args.port)
		io.recvuntil(b"+OK ")
		
		name = io.recvuntil(b"\r\n")
		print(name[:-2].decode())
		
		if not self.args.password:
			print("Password: ", end='')
			self.args.password = __import__("getpass").getpass()
			print()

		self.log.status("Authenticating...")
		io.sendline(b"USER %s" % self.args.username.encode())
		io.recv(timeout=5)
		io.sendline(b"PASS %s" % self.args.password.encode())
		
		msg = io.recv(timeout=5)

		if b"Logged in." in msg:
			self.log.success("Authentication complete.")
			self.interactive(io)
		else:
			self.log.failure("Authentication failed.")
			exit()

	def interactive(self, io):
		print("[*] Terminal opened. Type 'help' for help menu.\n")

		while 1:
			try:
				command = input(">> ").strip()
				cmd = command.lower()
				if cmd == "help":
					print("Commands:\n")
					print("ls\t\tLists messages.")
					print("cat\t\tReads a mail.")
					print("rm\t\tDeletes a mail.")
					print("reset\t\tRecovers the deleted messages.")
					print("sh\t\tRun a command in local system.")
					print("cls\t\tClears the screen.")
					print("clear\t\tClears the screen.")
					print("exit\t\tExits the server.\n")

				elif cmd == "ls":
					io.sendline(b"LIST")
					msg = io.recvuntil(b".\r\n")[4:-4].decode().replace('\r', '')
					print(msg)

				elif cmd[:3] == "cat":
					io.sendline(f"RETR {int(cmd[4:])}".encode())
					io.recv(4)
					while 1:
						out = io.recvline().decode().replace("\r\n\r\n", '')
						if "Message is deleted." in out:
							print("Message is deleted.")
							break
						else:
							if out == ".\r\n":
								break
							print(out.replace('\r', ''), end='')
				
				elif cmd[:2] == "rm":
					io.sendline(f"DELE {int(cmd[3:])}".encode())
					print("Message deleted.")

				elif cmd == "reset":
					io.sendline(b"RSET")
					print("Reset finished.")

				elif cmd[:2] == "sh":
					print(subprocess.getoutput())

				elif cmd in ("cls", "clear"):
					print(subprocess.getoutput("clear" if os.name != "nt" else "cls"))

				elif cmd == "exit":
					io.sendline(b"QUIT")
					print("Exit successfull.")
					exit()

				else:
					print("[!] Exception: Command not found. Type 'help' for help menu.")

			except (KeyboardInterrupt, EOFError):
				sys.exit()

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Pop3 client.", usage="%(prog)s <target> [port] -u <username> [-p] <password>")
	parser.add_argument(metavar="target", dest="target", help="Remote target address.")
	parser.add_argument(metavar="port", dest="port", help="Port of the remote server. (default: 110)", type=int, nargs='?', default=110)
	parser.add_argument("-u", "--username", metavar='', help="Username to login.", required=1)
	parser.add_argument("-p", "--password", metavar='', help="Password to login. Prompts if not provided.")

	args = parser.parse_args()

	POPPER(args).connect()
