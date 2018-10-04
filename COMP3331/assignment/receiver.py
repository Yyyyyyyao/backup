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
	global total_Dup_data
	global total_Dup_ACKs_sent


	receiver_port = int(sys.argv[1])

	print(receiver_port)
	file_name = sys.argv[2]
	print(file_name)
	# create the file
	file = open(file_name, 'wb')
	file.close()

	cumulated_ack = 0
	rcv_buffer = []

	receiverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	receiverSocket.bind(("localhost", receiver_port))

	start_time = time.time()*1000

	receiver_log = open("Receiver_log.txt", 'w')
	receiver_log.close()
	receiver_log = open("Receiver_log.txt", 'a')

	while True:
	    data, address = receiverSocket.recvfrom(receiver_port)
	    addr = (address[0], address[1])
	    pkt_receive = eval(data)

	    if (state == STATE_END):
			curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
			log_data = "rcv\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt_receive))+'\t'+str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
			receiver_log.write(log_data)
			sys.exit()

	    elif(is_fin(pkt_receive)):

	    	state = STATE_END
	    	curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
	    	log_data = "rcv\t"+str(curr_time)+"\tF\t"+str(get_seq(pkt_receive))+'\t'+ str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
	    	receiver_log.write(log_data)

	    	ack = get_seq(pkt_receive)+1
	    	seq = get_ack(pkt_receive)

	    	# set ACK_BIT
	    	flag = 0b010
	    	pkt_1 = packet(seq, ack, "", flag)

	    	log_data = "snd\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt_1))+'\t'+ str(len(get_data(pkt_1)))+'\t'+str(get_ack(pkt_1))+'\n'
	    	receiver_log.write(log_data)

	    	receiverSocket.sendto(str(pkt_1), addr)

	    	# set FIN
	    	flag = 0b001
	    	pkt_2 = packet(seq, ack, "", flag)

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
	    		receiver_log.write(log_data)

	    		ack = int(get_seq(pkt_receive))+1
	    		# set SYN and ACK_BIT
	    		flag = 0b110
	    		state = STATE_TRANS
	    		seq = random.randint(1,9)
	    		pkt_1 = packet(seq, ack, "", flag)

	    		receiverSocket.sendto(str(pkt_1), addr)

	    		log_data = "snd\t"+str(curr_time)+"\tSA\t"+str(seq)+'\t'+ str(len(get_data(pkt_1)))+'\t'+str(get_ack(pkt_1))+'\n'
	    		receiver_log.write(log_data)
	    
	    elif(state == STATE_TRANS):

	    	seq_receive = int(get_seq(pkt_receive))
	    	data_length = int(len(get_data(pkt_receive)))
	    	data = str(get_data(pkt_receive))

	    	if(is_ack(pkt_receive)):
	    		curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
	    		log_data = "rcv\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt_receive))+'\t'+str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
	    		receiver_log.write(log_data)

	    	else:

	    		curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
	    		log_data = "rcv\t"+str(curr_time)+"\tD\t"+str(get_seq(pkt_receive))+'\t'+str(len(get_data(pkt_receive)))+'\t'+str(get_ack(pkt_receive))+'\n'
	    		receiver_log.write(log_data)


	    		if(seq_receive != cumulated_ack):
	    			rcv_buffer.append(pkt_receive)


	    		elif(seq_receive == cumulated_ack):

	    			# rcv_buffer is empty 
	    			if(not rcv_buffer):
	    				cumulated_ack = seq_receive + data_length
	    				file = open(file_name, 'ab')
	    				file.write(data)
	    				file.close()

	    			else:
	    				# if the buffer is not empty
	    				# first write the expected arrived pkt
	    				cumulated_ack = seq_receive + data_length
	    				file = open(file_name, 'ab')
	    				file.write(data)
	    				file.close()

	    				i = 0

						# write the out of order pkts in the buffer
	    				for pkt in rcv_buffer:
	    					if(cumulated_ack == int(get_seq(pkt))):
	    						file = open(file_name, 'ab')
	    						file.write(data)
	    						file.close()
	    						cumulated_ack = int(get_seq(pkt))+int(len(get_data(pkt)))
	    						rcv_buffer.remove(i)
							i = i + 1


				flag = 0b010
				pkt = packet(1, str(cumulated_ack), '', flag)
				receiverSocket.sendto(str(pkt), addr)

				curr_time = float("{:6.2f}".format(time.time()*1000 - start_time))
				log_data = "snd\t"+str(curr_time)+"\tA\t"+str(get_seq(pkt))+'\t'+str(len(get_data(pkt)))+'\t'+str(get_ack(pkt))+'\n'
				receiver_log.write(log_data)
				






main()