#!/usr/bin/python3

import os
import sys
import argparse
import getpass
import termcolor
import subprocess

from pwn import *

class AuthenticationException(Exception):
	pass

class POP3:
	def __init__(self):
		if __name__ == '__main__':
			self.args()
			self.log = log.progress('')
			conn = self.connect()
			if conn:
				self.exec()

	def args(self):
		parser = argparse.ArgumentParser(description="Interactive POP3 Client.", usage="./%(prog)s [HOST] -p [PORT]")
		parser.add_argument(metavar="HOST", dest="host", help="IP or Domain of the target.")
		parser.add_argument("-p", metavar="PORT", help="Port of the pop3 server.", type=int, default=110, dest="port")
		if len(sys.argv) == 1:
			parser.print_usage(sys.stderr)
			exit(1)

		self.args = parser.parse_args()

		if self.args.port > 65535:
			self.log.failure("Wrong port specified.")
			exit()

	def connect(self):
		try:
			self.io = remote(self.args.host, self.args.port)
			self.io.recvuntil(b"+OK ")
			name = self.io.recvuntil(b"\r\n")
			print(name[:-2].decode())
			self.user = input("Username: ")
			print("Password: ")
			passwd = getpass.getpass()
			self.log.status("Authenticating...")
			cmd = ("USER {}".format(self.user)).encode()
			self.io.sendline(bytes(cmd))
			out = self.io.recvline()
			if b"+OK"in out:
				cmd = ("PASS {}".format(passwd)).encode()
				self.io.sendline(bytes(cmd))
				self.io.recvline()
				if b"Logged in." in self.io.recvline():
					self.log.success(f"Authentication complete, logged in to {self.args.host}:{self.args.port} as {self.user}")
					return True

				else:
					self.log.failure("Authentication Failed.")
					return False
					raise AuthenticationException

			else:
				self.log.failure("Authentication Failed.")
				return False
				raise AuthenticationException

		except AuthenticationException:
			self.log.failure("Authentication Failed.")
			return False
			self.io.close()
			exit()

		except pwnlib.exception.PwnlibException:
			pass

		except Exception as e:
			sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: {e}\n")
			return False
			self.io.close()
			exit()

	def exec(self):
		io = self.io
		print(f"\n[{termcolor.colored('+', 'green')}] Terminal opened. Type 'help' for HELP")

		while True:
			try:
				command = input(">> ").strip()
				cmd = command.lower()
				if cmd[0:4] == "help":
					try:
						print("Commands:\n")
						print("ls\t\t   Lists messages.")
						print("cat\t\t  Reads a mail.")
						print("rm\t\t   Deletes a mail.")
						print("reset\t\tRecovers the deleted messages.")
						print("sh\t\t   Run a command in shell.")
						print("clear\t\tClears the screen.")
						print("whoami\t   Prints the current user.")
						print("exit\t\t Exits this server.\n")

					except Exception as e:
						sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: {e}\n")

				if cmd[0:2] == "ls":
					try:
						io.sendline(b"LIST")
						msg = io.recvuntil(b".\r\n")[4:-4].decode()
						s = msg.replace("\r", "")
						print(s)
					except Exception as e:
						sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: {e}\n")

				elif cmd[0:3] == "cat":
					try:
						no = f"RETR {int(cmd[4:])}".encode()
						io.sendline(bytes(no))
						io.recv(4)
						while True:
							s = io.recvline()
							if not b"Message is deleted." in s:
								s = s.decode()
								s = s.replace("\r\n\r\n", "")
								if s == ".\r\n":
									break
								else:
									print(s.replace("\r", ""), end='')
							else:
								print(" Message is deleted.")
								break

					except Exception as e:
						sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: {e}\n")
				
				elif cmd[0:2] == "rm":
					try:
						no = f"DELE {int(cmd[3:])}".encode()
						io.sendline(bytes(no))
						io.recvline()
						print("Message deleted.")

					except Exception as e:
						sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: {e}\n")

				elif cmd[0:5] == "reset":
					try:
						io.sendline(b"RSET")
						io.recvline()
						print("Done.")

					except Exception as e:
						sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: {e}\n")

				elif cmd[0:2] == "sh":
					if len(cmd) <= 3:
						sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: Command not found.\n")

					else:
						try:
							out = subprocess.getoutput(command[3:])
							print(out)

						except Exception as e:
							sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: {e}\n")

				elif cmd[0:5] == "clear":
					try:
						out = subprocess.getoutput("clear")
						print(out)

					except Exception as e:
						sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: {e}\n")

				elif cmd[0:6] == "whoami":
					print(self.user, end="")

				elif cmd[0:4] == "exit":
					try:
						io.sendline(b"QUIT")
						out = io.recvline().replace(b"\r", b"")
						print(out.decode())

					except Exception as e:
						sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: {e}\n")

				else:
					if not cmd[0:4].encode() == b'help':
						sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: Command not found. Type help for HELP.\n")

			except KeyboardInterrupt:
				self.io.close()
				exit()

			except EOFError:
				break
				sys.exit()

if __name__ == '__main__':
	try:
		POP3()

	except (KeyboardInterrupt, EOFError):
		sys.stderr.write(f"[{termcolor.colored('-', 'red')}] Terminating...\n")
		exit()