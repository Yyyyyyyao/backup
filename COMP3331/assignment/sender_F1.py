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



def fourseg_termination(ack, seq, senderSocket, addr, sender_log, start_time):

	global state
	global total_segments

	# set FIN
	flag = 0b001

	pkt_1 = packet(seq, ack, '', flag, -2)

	senderSocket.sendto(str(pkt_1), addr)
	total_segments = total_segments + 1

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
				total_segments = total_segments + 1

				log_data = "snd\t"+str(curr_time)+"\tA\t"+str(seq)+'\t'+ str(len(get_data(pkt_2)))+'\t'+str(get_ack(pkt_2))+'\n' 
				sender_log.write(log_data)

				state = STATE_END
				log_data_structure = "===================================================================================\n"
				sender_log.write(log_data_structure)

				str1 = "Size of the file (in Bytes)\t\t\t\t\t\t\t" + str(total_data)+'\n'
				str2 = "Segments transmitted (including drop & RXT)\t\t\t"+str(total_segments)+'\n'
				str3 = "Number of Segments handled by PLD\t\t\t\t\t"+str(total_PLD)+'\n'
				str4 = "Number of Segments dropped\t\t\t\t\t\t\t"+str(total_drop)+'\n'
				str5 = "Number of Segments Corrupted\t\t\t\t\t\t"+str(total_corr)+'\n'
				str6 = "Number of Segments Re-ordered\t\t\t\t\t\t"+str(total_reorder)+'\n'
				str7 = "Number of Segments Duplicated\t\t\t\t\t\t"+str(total_dup)+'\n'
				str8 = "Number of Segments Delayed\t\t\t\t\t\t\t"+str(total_delay)+'\n'
				str9 = "Number of Retransmissions due to TIMEOUT\t\t\t"+str(total_timeout)+'\n'
				str10 = "Number of Fast RETRANSMISSION\t\t\t\t\t\t"+str(total_fast)+'\n'
				str11 = "Number of DUP ACKS received\t\t\t\t\t\t\t"+str(total_dupack)+'\n'

				sender_log.write(str1)
				sender_log.write(str2)
				sender_log.write(str3)
				sender_log.write(str4)
				sender_log.write(str5)
				sender_log.write(str6)
				sender_log.write(str7)
				sender_log.write(str8)
				sender_log.write(str9)
				sender_log.write(str10)
				sender_log.write(str11)

				sender_log.write(log_data_structure)
				sender_log.close()

				sys.exit()

			else:
				curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
				log_data = "rcv\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt_receive))+'\t'+ str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
				sender_log.write(log_data)

		except socket.timeout:
			print("TIME OUT in terminate")
			sys.exit()

def threeway_handshake(seq, senderSocket,addr, start_time, seed, sender_log):
	global state
	global total_segments

	if(state != STATE_INIT):
		print("ERROR: NOT TIME FOR HANDSHAKE")
		sys.exit()

	# flag: SYN ACK_BIT FIN
	# set SYN to 1 
	flag = 0b100

	# packet(seq, ack, data, flag)
	# create the first pkt
	pkt_1 = packet(seq, 0, "", flag, -2)

	# send the first pkt
	senderSocket.sendto(str(pkt_1), addr)
	total_segments = total_segments + 1

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
			total_segments = total_segments + 1

			# write log file
			log_data = "snd\t"+str(curr_time)+"\tA\t"+str(seq)+'\t'+ str(len(get_data(pkt_2)))+'\t'+str(get_ack(pkt_2))+'\n'
			sender_log.write(log_data)

			# for the sender side, connection is established 
			state = STATE_ESTAB

			return [seq, ack]
		
		else:

			print("receiver does not response")



	except socket.timeout:
		print("time out in handshake")
		sys.exit()

'''
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
'''
def PLD(sample_timer, pkt, start_time, senderSocket, addr, sender_log, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed, re_order_window, re_order_counter, retransmit_flag):
	
	global total_segments
	global total_PLD
	global total_drop
	global total_corr
	global total_reorder
	global total_dup
	global total_delay

	total_PLD = total_PLD + 1
	total_segments = total_segments + 1
	
	ran = random.random()

	valid = False

	if(retransmit_flag == True):
		log_header = "snd/RXT"
	else:
		log_header = "snd"


	if(len(re_order_window) > 0):
		if(re_order_counter == maxOrder):
			senderSocket.sendto(str(re_order_window[0]), addr)
			curr_time = float("{:6.2f}".format(time.time()*1000-start_time))
			log_data = log_header+"/rord\t"+str(curr_time)+'\tD\t'+str(get_seq(re_order_window[0]))+'\t'+str(len(get_data(re_order_window[0])))+'\t'+str(get_ack(re_order_window[0]))+'\n'
			sender_log.write(log_data)

			re_order_counter = 0
			del re_order_window[0]

		else:
			re_order_counter = re_order_counter + 1

	if(ran < pDrop):
		sent = 0
		total_drop = total_drop + 1
		curr_time = float("{:6.2f}".format(time.time()*1000-start_time))
		log_data = "drop\t"+str(curr_time)+'\tD\t'+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
		sender_log.write(log_data)

	else:
		ran = random.random()
		if(ran < pDuplicate):
			total_dup = total_dup + 1
			senderSocket.sendto(str(pkt), addr)
			senderSocket.sendto(str(pkt), addr)
			curr_time = float("{:6.2f}".format(time.time()*1000-start_time))
			log_data = log_header+'\t'+str(curr_time)+'\tD\t'+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
			log_data = log_header+"/dup\t"+str(curr_time)+'\tD\t'+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
			sender_log.write(log_data)
		else:
			ran = random.random()
			if(ran < pCorrupt):
				total_corr = total_corr + 1
				newpkt = sender_checksum_withError(pkt)

				senderSocket.sendto(str(newpkt), addr)
				curr_time = float("{:6.2f}".format(time.time()*1000-start_time))
				log_data = log_header+"/corr\t"+str(curr_time)+'\tD\t'+str(get_seq(newpkt))+'\t'+str(len(get_data(newpkt)))+'\t'+str(get_ack(newpkt))+'\n'
				sender_log.write(log_data)

			else:
				ran = random.random()
				if(ran < pOrder):
					if(len(re_order_window) == 0):
						total_reorder = total_reorder + 1
						re_order_window.append(pkt)
						re_order_counter = 0
				else:
					ran = random.random()
					if(ran < pDelay):
						total_delay = total_delay + 1
						delay = random.uniform(0, maxDelay)
						time.sleep(1)
						senderSocket.sendto(str(pkt), addr)
						curr_time = float("{:6.2f}".format(time.time()*1000-start_time))
						log_data = log_header+"/dely\t"+str(curr_time)+'\tD\t'+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
						sender_log.write(log_data)

					else:
						if(sample_timer == True):
							valid == True
						senderSocket.sendto(str(pkt), addr)
						curr_time = float("{:6.2f}".format(time.time()*1000-start_time))
						log_data = log_header+"\t"+str(curr_time)+'\tD\t'+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
						sender_log.write(log_data)

	return [re_order_window, re_order_counter, valid]


def sender_checksum_withError(pkt):

	correct_data = get_data(pkt)

	checksum = 0
	for byte in bytearray(correct_data):
		if(checksum == 0):
			error = int(byte) - 1
		checksum = checksum + int(byte)

	corrupted_byte = chr(error)
	data = corrupted_byte + correct_data[1:]

	newpkt = set_newData(pkt, data)
	newpkt = set_checksum(newpkt, checksum)

	return newpkt

def transfer(ack, ini_seq, seq, senderSocket, addr, data, sender_log, start_time, mws, mss, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed, gamma):

	pre_ack = -1
	counter = 0

	global total_data
	global total_segments
	global total_PLD
	global total_drop
	global total_corr
	global total_reorder
	global total_dup
	global total_delay
	global total_timeout
	global total_fast
	global total_dupack

	# initially, 
	# EstimatedRTT = 500 ms
	# DevRTT = 250 ms
	EstimatedRTT = 500
	DevRTT = 250
	TimeoutInterval = EstimatedRTT + 4*DevRTT

	window = []
	re_order_window = []
	re_order_counter = 0

	baseTime = time.time()*1000

	while(True):
		retransmit_flag = False
		window_size = mws/mss
		sample_timer = False
		sample_seq = -1
		# timeout

		if(time.time()*1000 - baseTime >= TimeoutInterval and len(window) > 0):

			total_timeout = total_timeout + 1

			baseWindowSeq = int(get_seq(window[0]))
			baseTime = time.time()*1000

			# see whether the data seg can hold the rest of data
			if((int(get_seq(window[0]))-ini_seq+mss) < len(data)):
				pkt_data = data[(baseWindowSeq-ini_seq):(baseWindowSeq+mss-ini_seq)]
			else:
				pkt_data = data[(baseWindowSeq-ini_seq):]

			flag = 0b000
			checksum = calculate_checksum(pkt_data)
			pkt = packet(baseWindowSeq, ack, pkt_data, flag, checksum)
			'''
			PLD(sender_log,start_time,senderSocket, pkt, addr,pDrop)
			'''
			retransmit_flag = True
			pld_list = PLD(sample_timer, pkt, start_time, senderSocket, addr, sender_log, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed, re_order_window, re_order_counter, retransmit_flag)
			re_order_window = pld_list[0]
			re_order_counter = pld_list[1]

		while(not window or len(window) < window_size and (seq-ini_seq) <= len(data)):

			sample_timer = False
			if(seq == ini_seq):
				sample_seq = seq
				sample_timer = True
				next_sample_seq = seq+mws

			if(seq == next_sample_seq):
				sample_seq = seq
				sample_timer = True
				next_sample_seq = seq+mws

			if(pre_ack >= seq):
				seq = pre_ack

			if((seq+mss-ini_seq) < len(data)):
				pkt_data = data[(seq-ini_seq):(seq-ini_seq)+mss]
			else:
				pkt_data = data[(seq-ini_seq):]

			flag = 0b000
			checksum = calculate_checksum(pkt_data)
			pkt = packet(seq, ack, pkt_data, flag, checksum)


			retransmit_flag = False
			pld_list = PLD(sample_timer, pkt, start_time, senderSocket, addr, sender_log, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed, re_order_window, re_order_counter, retransmit_flag)
			re_order_window = pld_list[0]
			re_order_counter = pld_list[1]
			valid = pld_list[2]

			if(valid == True):
				set_timer(pkt, time.time()*1000)
			else:
				set_timer(pkt, -1)

			window.append(pkt)
			windowBase = int(get_seq(window[0]))
			seq = seq+mss
			sample_timer = False

			'''
			PLD(sender_log,start_time,senderSocket, pkt, addr,pDrop)
			'''



		try:
			msg, address = senderSocket.recvfrom(1024)
			pkt_receive = eval(msg)

			if(is_ack(pkt_receive)):
				dupACK_flag = False
				cumulated_ACK = int(get_ack(pkt_receive))
				if((cumulated_ACK - ini_seq) >= len(data)):
					state = -1
					total_data = cumulated_ACK - ini_seq
					return [cumulated_ACK, ack]
				if(pre_ack == cumulated_ACK):
					counter += 1
					total_dupack = total_dupack + 1
					dupACK_flag = True
				if(counter >= 2):
					counter = 0
					total_fast = total_fast + 1
					seq = int(get_ack(pkt_receive))
					if((seq + mss - ini_seq) < len(data)):
						pkt_data = data[(seq-ini_seq) : (seq - ini_seq +mss)]
					else:
						pkt_data = data[(seq-ini_seq) :]

					'''
					for pkt in window:
						if(int(get_seq(pkt)) == seq):
							set_timer(pkt, -1)
					'''
					baseTime = time.time()*1000
					flag = 0b000
					checksum = calculate_checksum(pkt_data)
					pkt = packet(seq, ack, pkt_data, flag, checksum)
					'''
					PLD(sender_log,start_time,senderSocket, pkt, addr,pDrop)
					'''
					retransmit_flag = True
					pld_list = PLD(sample_timer, pkt, start_time, senderSocket, addr, sender_log, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed, re_order_window, re_order_counter, retransmit_flag)
					re_order_window = pld_list[0]
					re_order_counter = pld_list[1]

				if(dupACK_flag == True):
					curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
					log_data = "rcv/DA\t"+str(curr_time)+'\tA\t'+str(get_seq(pkt_receive))+'\t'+str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
					sender_log.write(log_data)
				else:

					curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
					log_data = "rcv\t"+str(curr_time)+'\tA\t'+str(get_seq(pkt_receive))+'\t'+str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
					sender_log.write(log_data)

				pre_ack = int(get_ack(pkt_receive))

				sampleRTT = -1
				# reset baseTime for the new ack
				# because the window is updated
				for pkt in window:
					if(int(get_seq(pkt)) == sample_seq):
						if(int(get_timer(pkt)) != -1 and (sample_seq+mss) == pre_ack):
							sampleRTT = time.time()*1000 - float(get_timer(pkt))
					if(int(int(get_seq(pkt))+int(len(get_data(pkt)))) > pre_ack):
						baseTime = time.time()*1000
					#if(int(get_seq(pkt))+int(len(get_data(pkt))) == pre_ack):
					#	if(int(get_timer(pkt)) != -1):
					#		sampleRTT = time.time()*1000 - float(get_timer(pkt))

				if(sampleRTT != -1):
				# new time interval
					EstimatedRTT = (1-0.125)*EstimatedRTT + 0.125*sampleRTT
					DevRTT = (1-0.25)*DevRTT + 0.25*abs(sampleRTT - EstimatedRTT)
					TimeoutInterval = EstimatedRTT + gamma*DevRTT

				window[:] = [pkt for pkt in window if int(int(get_seq(pkt))+int(len(get_data(pkt)))) > pre_ack]

		except socket.timeout:
			'''
			if ((int(get_seq(window[0])) + mss) < len(data)):
				data_segment = data[int(get_seq(window[0])):int(get_seq(window[0]))+mss]
			else:
				data_segment = data[int(get_seq(window[0])):]
			checksum = calculate_checksum(data_segment)
			p = packet(int(get_seq(window[0])), 1, data_segment, 0b000, checksum)
			retransmit_flag = True
			re_order_pkt = PLD(p, start_time, senderSocket, addr, sender_log, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed, re_order_window, re_order_counter, retransmit_flag)
			re_order_window = re_order_pkt[0]
			re_order_counter = re_order_pkt[1]
			'''
			

if __name__ == "__main__":

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
	maxDelay = float(sys.argv[13])/1000
	seed = int(sys.argv[14])

	# intialize the start time
	start_time = time.time()*1000

	global total_data
	global total_segments
	global total_PLD
	global total_drop
	global total_corr
	global total_reorder
	global total_dup
	global total_delay
	global total_timeout
	global total_fast
	global total_dupack



	total_data = 0
	total_segments = 0
	total_PLD = 0
	total_drop = 0
	total_corr = 0
	total_reorder = 0
	total_dup = 0
	total_delay = 0
	total_timeout = 0
	total_fast = 0
	total_dupack = 0

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

	random.seed(seed)

	seq = random.randint(1,9)

	# threeway handshake to establish the connection
	header = threeway_handshake(seq, senderSocket, addr, start_time, seed, sender_log)

	seq = header[0]
	ack = header[1]

	ini_seq = seq

	# open the test file
	try:
		file = open(file_name, 'rb')
		data = file.read()
		file.close()
	except:
		sys.exit("ERROR: cannot read the file")

	header = transfer(ack, ini_seq, seq, senderSocket, addr, data, sender_log, start_time, mws, mss, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed, gamma)

	seq = header[0]
	ack = header[1]
	#senderSocket.send(data)

	# sender_receive = senderSocket.recv(1024)

	# senderSocket.close()
	fourseg_termination(ack,seq, senderSocket, addr, sender_log, start_time)

