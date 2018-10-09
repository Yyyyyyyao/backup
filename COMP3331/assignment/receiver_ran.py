import sys
import random
import time
import socket
total = len(sys.argv)
cmdargs = str(sys.argv)



from packet import *

STATE_INIT = 0
STATE_TRANS = 1
STATE_END = 2

state = STATE_INIT

def main():
	global state
	global total_data
	global total_seg
	global total_data_seg
	global total_error
	global total_dup_receive
	global total_Dup_ACKs_sent


	total_data = 0
	total_seg = 0
	total_data_seg = 0
	total_error = 0
	total_dup_receive = 0
	total_Dup_ACKs_sent = 0



	first_pkt = False

	receiver_port = int(sys.argv[1])

	print(receiver_port)
	file_name = sys.argv[2]
	print(file_name)
	# create the file
	file = open(file_name, 'wb')
	file.close()

	cumulated_ack = 0
	rcv_buffer = []

	dup_ack = 0
	ini_rcv_seq = 0

	receiverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	receiverSocket.bind(("localhost", receiver_port))

	start_time = time.time()*1000

	receiver_log = open("Receiver_log.txt", 'w')
	receiver_log.close()
	receiver_log = open("Receiver_log.txt", 'a')

	seq = random.randint(1,9)

	while True:
	    data, address = receiverSocket.recvfrom(receiver_port)
	    addr = (address[0], address[1])
	    pkt_receive = eval(data)

	    if (state == STATE_END):
			curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
			log_data = "rcv\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt_receive))+'\t'+str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
			total_seg = total_seg + 1
			total_data_seg = total_seg - 4

			print(total_dup_receive)
			receiver_log.write(log_data)
			sys.exit()

	    elif(is_fin(pkt_receive)):

	    	state = STATE_END
	    	curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
	    	log_data = "rcv\t"+str(curr_time)+"\tF\t"+str(get_seq(pkt_receive))+'\t'+ str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
	    	total_seg = total_seg + 1
	    	receiver_log.write(log_data)


	    	total_data = int(get_ack(pkt_receive)) - ini_rcv_seq

	    	ack = get_seq(pkt_receive)+1
	    	seq = get_ack(pkt_receive)

	    	# set ACK_BIT
	    	flag = 0b010
	    	pkt_1 = packet(seq, ack, "", flag, -2)

	    	log_data = "snd\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt_1))+'\t'+ str(len(get_data(pkt_1)))+'\t'+str(get_ack(pkt_1))+'\n'
	    	receiver_log.write(log_data)

	    	receiverSocket.sendto(str(pkt_1), addr)

	    	# set FIN
	    	flag = 0b001
	    	pkt_2 = packet(seq, ack, "", flag, -2)

	    	log_data = "snd\t"+str(curr_time)+"\tF\t"+str(get_seq(pkt_2))+'\t'+ str(len(get_data(pkt_2)))+'\t'+str(get_ack(pkt_2))+'\n'
	    	receiver_log.write(log_data)
	    	receiverSocket.sendto(str(pkt_2), addr)

	    elif (state == STATE_INIT):
	    	total_data = 0
	    	total_seg = 0
	    	total_Dup_ACKs_sent = 0
	    	if(is_syn(pkt_receive)):

	    		curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
	    		
	    		log_data = "rcv\t"+str(curr_time)+"\tS\t"+str(get_seq(pkt_receive))+'\t'+ str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
	    		total_seg = total_seg + 1
	    		receiver_log.write(log_data)

	    		ack = int(get_seq(pkt_receive))+1
	    		# set SYN and ACK_BIT
	    		flag = 0b110
	    		state = STATE_TRANS
	    		
	    		pkt_1 = packet(seq, ack, "", flag, -2)

	    		receiverSocket.sendto(str(pkt_1), addr)

	    		seq = ack

	    		cumulated_ack = ack

	    		ini_rcv_seq = ack

	    		log_data = "snd\t"+str(curr_time)+"\tSA\t"+str(seq)+'\t'+ str(len(get_data(pkt_1)))+'\t'+str(get_ack(pkt_1))+'\n'
	    		receiver_log.write(log_data)
	    
	    elif(state == STATE_TRANS):
	    	seq_receive = int(get_seq(pkt_receive))
	    	data_length = int(len(get_data(pkt_receive)))
	    	data = str(get_data(pkt_receive))
	    	checksum_header = get_checksum(pkt_receive)
	    	checksum_data = calculate_checksum(data)
	    	dup_sent = False


	    	if(checksum_data != checksum_header):
	    		total_error = total_error + 1
	    	else:
		    	if(is_ack(pkt_receive)):
		    		curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
		    		log_data = "rcv\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt_receive))+'\t'+str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
		    		total_seg = total_seg + 1
		    		receiver_log.write(log_data)
		    	else:

		    		curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
		    		log_data = "rcv\t"+str(curr_time)+"\tD\t"+str(get_seq(pkt_receive))+'\t'+str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
		    		total_seg = total_seg + 1
		    		receiver_log.write(log_data)


		    		if(seq_receive == seq and not first_pkt):

		    			first_pkt = True
		    			cumulated_ack = seq_receive+data_length
		    			write_to_file(file_name, str(get_data(pkt_receive)))
		    			pre_seq = int(get_seq(pkt_receive))
		    			
		    		elif (cumulated_ack == seq_receive and first_pkt):

		    			if(pre_seq == seq_receive and pre_seq >= cumulated_ack):
		    				total_dup_receive = total_dup_receive + 1
		    				dup_sent = True
		    			else:
		    				pre_seq = seq_receive
			    			if(not rcv_buffer):
			    				cumulated_ack = seq_receive+data_length
			    				write_to_file(file_name, str(get_data(pkt_receive)))
			    			else:
			    				write_to_file(file_name, str(get_data(pkt_receive)))
			    				cumulated_ack = seq_receive+data_length
			    				for z in rcv_buffer:
			    					if (int(cumulated_ack) ==int(get_seq(z))):
			    						write_to_file(file_name, str(get_data(z)))
			    						cumulated_ack = int(get_seq(z))+int(len(get_data(z)))
			    				rcv_buffer[:] = [value for value in rcv_buffer if int(get_seq(value)) > int(cumulated_ack)]

		    		else:
		    			if(pre_seq == seq_receive and pre_seq >= cumulated_ack):
		    				total_dup_receive = total_dup_receive + 1
		    				dup_sent = True
		    			else:
		    				pre_seq = seq_receive
		    				rcv_buffer.append(pkt_receive)

		    		if(not dup_sent):
			    		flag = 0b010
			    		pkt = packet(1, cumulated_ack, '', flag, -2)
			    		receiverSocket.sendto(str(pkt), addr)
			    		if(dup_ack == int(get_ack(pkt))):
			    			curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
			    			log_data = "snd/DA\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
			    			total_Dup_ACKs_sent = total_Dup_ACKs_sent + 1
			    			receiver_log.write(log_data)
			    		else:
			    			dup_ack = int(get_ack(pkt))
			    			curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
			    			log_data = "snd\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
			    			receiver_log.write(log_data)
		    		#curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
		    		#log_data = "snd\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
		    		#receiver_log.write(log_data)

	    	'''
	    	seq_receive = int(get_seq(pkt_receive))
	    	data_length = int(len(get_data(pkt_receive)))
	    	data = str(get_data(pkt_receive))
	    	checksum_header = get_checksum(pkt_receive)
	    	checksum_data = calculate_checksum(data)
	    	if(checksum_data == checksum_header):

		    	if(is_ack(pkt_receive)):
		    		curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
		    		log_data = "rcv\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt_receive))+'\t'+str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
		    		receiver_log.write(log_data)

		    	else:

		    		curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
		    		log_data = "rcv\t"+str(curr_time)+"\tD\t"+str(get_seq(pkt_receive))+'\t'+str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
		    		receiver_log.write(log_data)

		    		if(cumulated_ack == seq_receive):

		    			# rcv_buffer is empty 
		    			if(not rcv_buffer):
		    				cumulated_ack = seq_receive + data_length
		    				write_to_file(file_name, str(get_data(pkt_receive)))


		    			else:
		    				# if the buffer is not empty
		    				# first write the expected arrived pkt
		    				write_to_file(file_name, str(get_data(pkt_receive)))
		    				cumulated_ack = seq_receive + data_length

							# write the out of order pkts in the buffer
		    				for pkt in rcv_buffer:
		    					if(int(cumulated_ack) == int(get_seq(pkt))):
		    						write_to_file(file_name, str(get_data(pkt)))
		    						cumulated_ack = int(get_seq(pkt))+int(len(get_data(pkt)))

		    				rcv_buffer[:] = [pkt for pkt in rcv_buffer if int(get_seq(pkt)) > int(cumulated_ack)]
		    		else:
		    			rcv_buffer.append(pkt_receive)


					flag = 0b010
					pkt = packet(1, str(cumulated_ack), '', flag, -2)
					receiverSocket.sendto(str(pkt), addr)

					if(dup_ack == int(get_ack(pkt))):
						curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
						log_data = "snd/DA\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
						receiver_log.write(log_data)

					else:
						dup_ack = int(get_ack(pkt))
						curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
						log_data = "snd\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
						receiver_log.write(log_data)

			'''






def write_to_file(file_name, data):
	with open(file_name, "ab") as file:
		file.write(data)

main()
