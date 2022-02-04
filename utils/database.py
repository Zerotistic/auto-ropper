from pwn import *
import sqlite3

class Database():
	def __init__(self, binary, aslr):
		self.md5sum = pwnlib.util.hashes.md5filehex(binary)
		self.aslr = aslr
		self.db = sqlite3.connect('./database/database')
		self.cursor = self.db.cursor()
		self.create_database()
		self.cursor.execute("SELECT md5sum FROM binaryInfo")
		data = self.cursor.fetchall()
		self.pwn_state = any(self.md5sum in data for data in data)

	def create_database(self):
		self.cursor.execute("DROP TABLE IF EXISTS binaryInfo")
		self.cursor.execute("DROP TABLE IF EXISTS payload")
		self.cursor.execute('CREATE TABLE IF NOT EXISTS binaryInfo (md5sum varchar(50) PRIMARY KEY, offset int, libc varchar(100), aslr int)')
		self.cursor.execute('CREATE TABLE IF NOT EXISTS payload (md5sum varchar(50), payload1 varchar(1000), payload2 varchar(1000), FOREIGN KEY (md5sum) REFERENCES binaryInfo(md5sum) ON DELETE SET null)')

	def add_basics(self):
		request = "INSERT INTO binaryInfo (md5sum, aslr) VALUES (?,?)"
		self.cursor.execute(request, (self.md5sum, self.aslr))
		self.db.commit()

	def add_offset(self, offset):
		self.cursor.execute('UPDATE binaryInfo SET offset = ? WHERE md5sum = ?',(offset, self.md5sum))
		self.db.commit()

	def add_libc(self, libc):
		self.cursor.execute('UPDATE binaryInfo SET libc = ? WHERE md5sum = ?',(libc, self.md5sum))
		self.db.commit()

	def prep_md5sum(self):
		request = "INSERT INTO payload (md5sum) VALUES (?)"
		self.cursor.execute(request, (self.md5sum,))
		self.db.commit()

	def add_p1(self, p1):
		self.cursor.execute("UPDATE payload SET payload1 = ? WHERE md5sum = ?", (p1, self.md5sum))
		self.db.commit()

	def add_p2(self, p2):
		self.cursor.execute("UPDATE payload SET payload2 = ? WHERE md5sum = ?", (p2, self.md5sum))
		self.db.commit()