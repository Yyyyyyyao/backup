import sys
import random
import time
import socket
total = len(sys.argv)

from packet import *

STATE_INIT = 0
STATE_ESTAB = 1
STATE_END = 2

state = STATE_INIT

# argv: $ .py host_name  port  file_name  MWS  MSS
def main():

	# take in all the argv
	receiver_host_ip = sys.argv[1]
	receiver_port = int(sys.argv[2])
	print(receiver_port)
	file_name = sys.argv[3]
	mws = int(sys.argv[4])
	mss = int(sys.argv[5])
	gamma = int(sys.argv[6])
	pDrop = float(sys.argv[7])
	pDuplicate = float(sys.argv[8])
	pCorrupt = float(sys.argv[9])
	pOrder = float(sys.argv[10])
	maxOrder = int(sys.argv[11])
	pDelay = float(sys.argv[12])
	maxDelay = float(sys.argv[13])*1000
	seed = int(sys.argv[14])

	# intialize the start time
	start_time = time.time()*1000

	# initialize the socket
	# Setting a timeout of None disables timeouts on socket operations
	# s.settimeout(None) is equivalent to s.setblocking(1)
	senderSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	senderSocket.settimeout(1)
	addr = (receiver_host_ip, receiver_port)

	# create a Sender_log file
	sender_log = open("Sender_log.txt", 'w')
	sender_log.close()
	# append data on the exiting Sender_log file
	sender_log = open("Sender_log.txt", 'a')

	# threeway handshake to establish the connection
	threeway_handshake(senderSocket, addr, start_time, seed, sender_log)

	# open the test file
	try:
		file = open(file_name, 'rb')
		data = file.read()
		file.close()
	except:
		sys.exit("ERROR: cannot read the file")

	transfer(senderSocket, addr, data, sender_log, start_time, mws, mss, pDrop)

	#senderSocket.send(data)

	# sender_receive = senderSocket.recv(1024)

	# senderSocket.close()
	fourseg_termination(senderSocket, addr, sender_log, start_time)

def threeway_handshake(senderSocket,addr, start_time, seed, sender_log):
	global state

	if(state != STATE_INIT):
		print("ERROR: NOT TIME FOR HANDSHAKE")
		sys.exit()

	# generate a random number for seq
	seq = random.randint(1,9)

	# flag: SYN ACK_BIT FIN
	# set SYN to 1 
	flag = 0b100

	# packet(seq, ack, data, flag)
	# create the first pkt
	pkt_1 = packet(seq, 0, "", flag, -2)

	# send the first pkt
	senderSocket.sendto(str(pkt_1), addr)

	# calculate the current time
	curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))

	#log_data = <event> <time> <type of pkt> <seq> <data size> <ack> 
	log_data = "snd\t"+str(curr_time)+"\tS\t"+str(seq)+'\t'+ str(len(get_data(pkt_1)))+'\t'+str(get_ack(pkt_1))+'\n'
	sender_log.write(log_data)

	# timeout exception
	try:

		# receive the pkt from the receiver
		pkt_receive, addr = senderSocket.recvfrom(1024)
		pkt_receive = eval(pkt_receive)
		ack_receive = get_ack(pkt_receive)

		# write log file
		log_data = "rcv\t"+str(curr_time)+"\tSA\t"+str(get_seq(pkt_receive))+'\t'+ str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
		sender_log.write(log_data)

		# justify whether this pkt has SYNACK flag and ack = seq+1
		if(is_syn(pkt_receive) and is_ack(pkt_receive) and (ack_receive == seq+1)):
			
			seq = ack_receive
			ack = get_seq(pkt_receive)+1

			# set ACK
			flag = 0b010

			# send pkt_2
			pkt_2 = packet(seq, ack, "", flag, -2)

			senderSocket.sendto(str(pkt_2), addr)

			# write log file
			log_data = "snd\t"+str(curr_time)+"\tA\t"+str(seq)+'\t'+ str(len(get_data(pkt_2)))+'\t'+str(get_ack(pkt_2))+'\n'
			sender_log.write(log_data)

			# for the sender side, connection is established 
			state = STATE_ESTAB

			return
		
		else:

			print("receiver does not response")



	except socket.timeout:
		print("time out in handshake")
		sys.exit()


def PLD(log,start,sender, p, addr,pdrop):

	rand = random.random()
	if (rand > pdrop):
		sender.sendto(str(p), addr)
		curr_time = time.time()*1000-start
		msg = 'snd\t'+str(curr_time)+'\tD\t'+str(get_seq(p))+'\t'+str(len(get_data(p)))+'\t'+str(get_ack(p))+'\n'
		log.write(msg)
	else:
		curr_time = time.time()*1000-start
		msg = 'drop\t'+str(curr_time)+'\tD\t'+str(get_seq(p))+'\t'+str(len(get_data(p)))+'\t'+str(get_ack(p))+'\n'
		log.write(msg)

def transfer(senderSocket, addr, data, sender_log, start_time, mws, mss, pDrop):

	baseTime = time.time()*1000
	pre_ack = -1
	counter = 0

	# initially, 
	# EstimatedRTT = 500 ms
	# DevRTT = 250 ms
	EstimatedRTT = 500
	DevRTT = 250
	TimeoutInterval = EstimatedRTT + 4*DevRTT

	window = []

	seq = 0

	while(True):

		window_size = mws/mss

		if(time.time()*1000 - baseTime >= TimeoutInterval and len(window) > 0 and int(windowBase) == int(get_seq(window[0]))):
			baseWindowSeq = int(get_seq(window[0]))
			baseTime = time.time()*1000

			# see whether the data seg can hold the rest of data
			if((int(get_seq(window[0]))+mss) < len(data)):
				pkt_data = data[baseWindowSeq:(baseWindowSeq+mss)]
			else:
				pkt_data = data[baseWindowSeq:]

			flag = 0b000
			pkt = packet(baseWindowSeq, 1, pkt_data, flag, -2)
			PLD(sender_log,start_time,senderSocket, pkt, addr,pDrop)

		while(not window or len(window) < window_size and seq <= len(data)):
			# timeout 
			'''
			if(time.time()*1000 - baseTime >= TimeoutInterval and len(window) > 0 and int(windowBase) == int(get_seq(window[0]))):
				baseWindowSeq = int(get_seq(window[0]))
				baseTime = time.time()*1000

				# see whether the data seg can hold the rest of data
				if((int(get_seq(window[0]))+mss) < len(data)):
					pkt_data = data[baseWindowSeq:(baseWindowSeq+mss)]
				else:
					pkt_data = data[baseWindowSeq:]

				flag = 0b000
				pkt = packet(baseWindowSeq, 1, pkt_data, flag)
				PLD(sender_log,start_time,senderSocket, pkt, addr,pDrop)
			
				senderSocket.sendto(str(pkt), addr)

				
				curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
				senderSocket.sendto(str(pkt), addr)
				log_data = "snd/Time\t"+str(curr_time)+"\tD\t"+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
				sender_log.write(log_data)
			'''

			if((seq+mss) < len(data)):
				pkt_data = data[seq:seq+mss]
			else:
				pkt_data = data[seq:]

			flag = 0b000
			pkt = packet(seq, 1, pkt_data, flag, -2)

			window.append(pkt)
			windowBase = int(get_seq(window[0]))
			seq = seq+mss
			PLD(sender_log,start_time,senderSocket, pkt, addr,pDrop)
			'''
			curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
			senderSocket.sendto(str(pkt), addr)
			log_data = "snd\t"+str(curr_time)+'\tD\t'+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
			sender_log.write(log_data)
			'''

		try:
			msg, address = senderSocket.recvfrom(1024)
			pkt_receive = eval(msg)
			curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
			log_data = "rcv\t"+str(curr_time)+'\tA\t'+str(get_seq(pkt_receive))+'\t'+str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
			sender_log.write(log_data)

			if(is_ack(pkt_receive)):

				cumulated_ACK = int(get_ack(pkt_receive))
				if(cumulated_ACK >= len(data)):
					state = -1
					break
				if(pre_ack == cumulated_ACK):
					counter += 1
				if(counter >= 2):
					counter = 0
					seq = int(get_ack(pkt_receive))
					if(seq + mss < len(data)):
						pkt_data = data[seq : seq+mss]
					else:
						pkt_data = data[seq :]

					flag = 0b000
					pkt = packet(seq, 1, pkt_data, flag, -2)
					PLD(sender_log,start_time,senderSocket, pkt, addr,pDrop)
					'''
					senderSocket.sendto(str(pkt), addr)
					curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
					log_data = "snd/fast\t"+str(curr_time)+'\tD\t'+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
					sender_log.write(log_data)
					'''

				pre_ack = int(get_ack(pkt_receive))

				# reset baseTime for the new ack
				# because the window is updated
				for pkt in window:
					if(int(int(get_seq(pkt))+int(len(get_data(pkt)))) > pre_ack):
						baseTime = time.time()*1000

				window[:] = [pkt for pkt in window if int(int(get_seq(pkt))+int(len(get_data(pkt)))) > pre_ack]

		except socket.timeout:
			'''
			seq = int(get_seq(window[0]))
			if(seq + mss < len(data)):
				pkt_data = data[seq:seq+mss]
			else:
				pkt_data = data[seq:]
			flag = 0b000
			pkt = packet(seq, 1, pkt_data, flag, -2)
			
			curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
			log_data = "snd/Stimeout\t"+str(curr_time)+'\t'+str(seq)+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
			sender_log.write(log_data)
	
			PLD(sender_log,start_time,senderSocket, pkt, addr,pDrop)
			'''
							



def fourseg_termination(senderSocket, addr, sender_log, start_time):

	global state

	seq = random.randint(1,9)
	# set FIN
	flag = 0b001

	pkt_1 = packet(seq, 0, '', flag, -2)

	senderSocket.sendto(str(pkt_1), addr)

	curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
	log_data = "snd\t"+str(curr_time)+"\tF\t"+str(seq)+'\t'+ str(len(get_data(pkt_1)))+'\t'+str(get_ack(pkt_1))+'\n'
	sender_log.write(log_data)

	while True:
		try:
			msg, address = senderSocket.recvfrom(1024)
			pkt_receive = eval(msg)


			if(is_fin(pkt_receive)):

				curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
				log_data = "rcv\t"+str(curr_time)+"\tF\t"+str(get_seq(pkt_receive))+'\t'+ str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
				sender_log.write(log_data)

				seq = get_ack(pkt_receive)
				ack = get_seq(pkt_receive)+1

				# set ACK_BIT to 1
				flag = 0b010
				pkt_2 = packet(seq, ack, "", flag, -2)

				senderSocket.sendto(str(pkt_2), addr)

				log_data = "snd\t"+str(curr_time)+"\tA\t"+str(seq)+'\t'+ str(len(get_data(pkt_2)))+'\t'+str(get_ack(pkt_2))+'\n' 
				sender_log.write(log_data)

				state = STATE_END
				sender_log.close()

				sys.exit()

			else:
				curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
				log_data = "rcv\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt_receive))+'\t'+ str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
				sender_log.write(log_data)

		except socket.timeout:
			print("TIME OUT in terminate")
			sys.exit()










main()

