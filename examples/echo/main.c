/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <unistd.h>

static volatile bool force_quit;

#define RTE_LOGTYPE_DRTR RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 1 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 4096
#define RTE_TEST_TX_DESC_DEFAULT 4096
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr port_eth_addr[RTE_MAX_ETHPORTS];

/* ip addresses of ports */
static uint8_t port_ip_addr[RTE_MAX_ETHPORTS][4];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int l2fwd_rx_queue_per_lcore = 1;

/* slow mode disabled by default */
static int slow_mode_enabled = 0;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
#define NICE_VIEW 0

#define RESET   "\033[0m"
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */
#define GREEN   "\033[32m"      /* Green */
#define RED   "\x1B[31m" /* Red */
#define BLUE   "\x1B[34m" /* BLUE */

#define NL printf("\n");

int alarm_stop = 0;
unsigned int alarm_period = 500000;

struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.offloads = DEV_RX_OFFLOAD_CRC_STRIP,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
	uint64_t tx_prev;
	uint64_t rx_prev;
	uint64_t dropped_prev;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 1; /* default period is 10 seconds */

static uint32_t sec_counter = 0;

struct callback_numbers {
        uint64_t total_cycles;
        uint64_t total_pkts;
		uint64_t pkt_size;
		uint64_t aps;
} ;
struct callback_numbers callback_numbers_port[RTE_MAX_ETHPORTS];



/* Print out statistics on packets dropped */
static void
print_stats(void)
{
        uint64_t total_packets_dropped, total_packets_tx, total_packets_rx, total_packets_dropped_rate, total_packets_tx_rate, total_packets_rx_rate;
        unsigned portid;

        total_packets_dropped = 0;
        total_packets_tx = 0;
        total_packets_rx = 0;
        total_packets_dropped_rate = 0;
        total_packets_tx_rate = 0;
        total_packets_rx_rate = 0;

	sec_counter++;


        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

	

                /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf(RED "\n-= echo v0.1 =-\n" RESET);

        printf("\nPort statistics===========");

        for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
                /* skip disabled ports */
                if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
                        continue;
		printf("\nPORT %u  (%02X:%02X:%02X:%02X:%02X:%02X)",
				portid,
				port_eth_addr[portid].addr_bytes[0],
				port_eth_addr[portid].addr_bytes[1],
				port_eth_addr[portid].addr_bytes[2],
				port_eth_addr[portid].addr_bytes[3],
				port_eth_addr[portid].addr_bytes[4],
				port_eth_addr[portid].addr_bytes[5]);

		printf(" IP %u.%u.%u.%u", 
		port_ip_addr[portid][0],
		port_ip_addr[portid][1],
		port_ip_addr[portid][2],
		port_ip_addr[portid][3]);

			printf(	//"\nPackets received: %16"PRIu64
			    //"\nPackets sent: %20"PRIu64
				//"\nPackets dropped: %17"PRIu64
				GREEN "\nPackets received/s: %24"PRIu64 RESET
				GREEN "\nPackets sent/s: %28"PRIu64 RESET
			    GREEN "\nPackets dropped/s: %25"PRIu64 RESET,

//				port_statistics[portid].rx,
//				port_statistics[portid].tx,
//				port_statistics[portid].dropped,
				port_statistics[portid].rx-port_statistics[portid].rx_prev,
				port_statistics[portid].tx-port_statistics[portid].tx_prev,
			    port_statistics[portid].dropped-port_statistics[portid].dropped_prev);
		
                total_packets_dropped += port_statistics[portid].dropped;
                total_packets_rx += port_statistics[portid].rx;
                total_packets_tx += port_statistics[portid].tx;
	        total_packets_dropped_rate += port_statistics[portid].dropped-port_statistics[portid].dropped_prev;
	        total_packets_rx_rate += port_statistics[portid].rx-port_statistics[portid].rx_prev;
			total_packets_tx_rate += port_statistics[portid].tx-port_statistics[portid].tx_prev;


		port_statistics[portid].rx_prev=port_statistics[portid].rx;
		port_statistics[portid].tx_prev=port_statistics[portid].tx;
		port_statistics[portid].dropped_prev=port_statistics[portid].dropped;

		NL
		printf(GREEN "APS: %u" RESET, callback_numbers_port[portid].aps);


        }
        printf("\nAggregate statistics==========="
//                   "\nTotal packets received: %10"PRIu64
//                   " | Total packets sent: %14"PRIu64
//                   " | Total packets dropped: %11"PRIu64
                   GREEN "\nTotal packets received/s: %18"PRIu64 RESET
                   GREEN "\nTotal packets sent/s: %22"PRIu64 RESET
                   GREEN "\nTotal packets dropped/s: %19"PRIu64 RESET
//                   GREEN "\nTotal packets processed by VNF/s: %10"PRIu64 RESET
		   "\n",
//                   total_packets_rx,
//                   total_packets_tx,
//                   total_packets_dropped,
                   total_packets_rx_rate,
                   total_packets_tx_rate,
                   total_packets_dropped_rate);
//                   total_packets_tx_rate+total_packets_rx_rate);




}



/*static uint16_t
add_timestamps(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
        struct rte_mbuf **pkts, uint16_t nb_pkts, void *_ __rte_unused)
{
    unsigned i;
    uint64_t now = rte_rdtsc();

    for (i = 0; i < nb_pkts; i++)
        pkts[i]->udata64 = now;

    return nb_pkts;
}*/

static uint16_t
calc_latency(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
        struct rte_mbuf **pkts, uint16_t nb_pkts, void *_ __rte_unused)
{
    uint64_t cycles = 0;
    uint64_t now = rte_rdtsc();
    unsigned i;

    /*for (i = 0; i < nb_pkts; i++)
        cycles += now - pkts[i]->udata64;

    latency_numbers.total_cycles += cycles;*/

    callback_numbers_port[port].total_pkts += nb_pkts;

    if (callback_numbers_port[port].total_pkts > (9ULL)) {
        //printf("Latency = %"PRIu64" cycles\n",
        //        latency_numbers.total_cycles / latency_numbers.total_pkts);

		//printf("No of packets: %u", callback_numbers_port[port].total_pkts);
		//NL

		callback_numbers_port[port].aps=callback_numbers_port[port].pkt_size/10;
		//printf("APS on port %u: %u", port , callback_numbers_port[port].aps);
		//NL

		callback_numbers_port[port].pkt_size = 0;
        callback_numbers_port[port].total_cycles = callback_numbers_port[port].total_pkts = 0;
	//print_stats();
    }

    return nb_pkts;
}

static void
handle_rx(struct rte_mbuf *pkt, unsigned portid)
{
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;
	struct ether_hdr *ethhdr;
	struct ipv4_hdr *iphdr;
	uint32_t dst_addr, src_addr;
	void *tmp;
	uint8_t eth_dst[6], *hex, temp8[6];
	uint16_t cksum;
	int ip_dst;

	ethhdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	
	//printf(GREEN "Packet received on port_%u:" RESET, portid);

	//NL

	//printf("pkt_len %u, data_len %u \n", pkt->pkt_len, pkt->data_len);
	callback_numbers_port[portid].pkt_size += pkt->pkt_len;


	hex = rte_pktmbuf_mtod(pkt, uint8_t*);

	/*
	printf("Buffer hex: \n");
	for(int i=0; i<6; i++){
		printf("%02x ", hex[i]);
	} printf(BLUE "L2DST " RESET);
	for(int i=6; i<12; i++){
		printf("%02x ", hex[i]);
	} printf(BLUE "L2SRC " RESET);
	for(int i=12; i<14; i++){
		printf("%02x ", hex[i]);
	} printf(BLUE "TYP -> " RESET);*/

	//check packet type
	if (ethhdr->ether_type == 0x0608){     /*           ARP            */
		//printf("ARP\n");

		/*printf("who-has: ");
		for(int i=38; i<42; i++){
			printf("%u ", hex[i]);
		} 
		NL*/

		if(memcmp(&hex[38], &port_ip_addr[portid][0], sizeof(uint8_t)*4) == 0){
			//printf("MATCH\n");
		}else return;

		/*printf("tell: ");
		for(int i=28; i<32; i++){
			printf("%02x ", hex[i]);
		}*/
		//NL

		//swap eth/l2 addresses
		memcpy(&ethhdr->d_addr.addr_bytes[0], &ethhdr->s_addr.addr_bytes[0], 6);
		// set eth source address
		memcpy(&ethhdr->s_addr.addr_bytes[0], &port_eth_addr[portid].addr_bytes[0], 6);

		//set opcode to 0x02 (arp reply)
		hex[21] = 0x02;

		//populate ARP sender details w/ source l2 and l3 (NOTE: ignoring arp target)
		memcpy(&hex[22], &port_eth_addr[portid].addr_bytes[0], 6);
		memcpy(&hex[28], &hex[38], 4);

		buffer = tx_buffer[portid];
		sent = rte_eth_tx_buffer(portid, 0, buffer, pkt);
		if (sent)
		port_statistics[portid].tx += sent;	

		return;	

	} else
	if (ethhdr->ether_type == 0x08){          /*                  IP                    */

		iphdr = (struct ipv4_hdr *)(ethhdr + 1);

		if(hex[23] == 0x01){			/*			ICMP			*/
			//printf("IP" BLUE " PROTO ->" RESET " ICMP ");

			if(hex[34] == 0x08){	// REQUEST
				//printf(" REQ");

				//swap eth/l2 addresses
				memcpy(&ethhdr->d_addr.addr_bytes[0], &ethhdr->s_addr.addr_bytes[0], 6);
				// set eth source address
				memcpy(&ethhdr->s_addr.addr_bytes[0], &port_eth_addr[portid].addr_bytes[0], 6);

				//set opcode to 0x00 (reply)
				hex[34] = 0x00;

				//swap ip/l3 addresses
				ip_dst = iphdr->dst_addr;
				iphdr->dst_addr = iphdr->src_addr;
				iphdr->src_addr = ip_dst;
			} 
			else if(hex[34] == 0x00){	// RESPONSE
				//printf(" RESP");
			} 

			
		} else { 		/*		NOT ICMP		*/

			/*	bounce traffic	*/

			//swap eth/l2 addresses
			memcpy(&ethhdr->d_addr.addr_bytes[0], &ethhdr->s_addr.addr_bytes[0], 6);
			// set eth source address
			memcpy(&ethhdr->s_addr.addr_bytes[0], &port_eth_addr[portid].addr_bytes[0], 6);

			//swap ip/l3 addresses
			ip_dst = iphdr->dst_addr;
			iphdr->dst_addr = iphdr->src_addr;
			iphdr->src_addr = ip_dst;

		}
	
		// calculate cksum
		iphdr->hdr_checksum = 0;
		cksum = rte_ipv4_cksum(iphdr);
		iphdr->hdr_checksum = cksum;

		//iphdr->time_to_live--;
		//iphdr->hdr_checksum++;

	buffer = tx_buffer[portid];
	sent = rte_eth_tx_buffer(portid, 0, buffer, pkt);
	if (sent)
		port_statistics[portid].tx += sent;

	}

	//NL


}

/* main worker loop - gets started on each lcore */
static void
default_worker_lcore_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	int sent;
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, DRTR, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, DRTR, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);

	}

	while (!force_quit) {

 if (slow_mode_enabled == 1){
                        usleep(1000);
                }
				
		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_rx_port; i++) {

				//portid = l2fwd_dst_ports[qconf->rx_port_list[i]];
				portid = qconf->rx_port_list[i];
				buffer = tx_buffer[portid];

				sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
				if (sent)
					port_statistics[portid].tx += sent;

			}
			prev_tsc = cur_tsc;
		}  

		/*
		 * Read packet from RX queues
		 */
 		for (i = 0; i < qconf->n_rx_port; i++) {

 			portid = qconf->rx_port_list[i];
 			nb_rx = rte_eth_rx_burst(portid, 0,
 						 pkts_burst, MAX_PKT_BURST);

 			port_statistics[portid].rx += nb_rx;

 			for (j = 0; j < nb_rx; j++) {
 				m = pkts_burst[j];
 				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
 				handle_rx(m, portid);
 			}
		}

	}
}

/* main timer */
void on_alarm(int signal)
{
	if(alarm_stop) return;
	else ualarm(alarm_period,alarm_period);

	//printf("\nTIME\n");
	print_stats();

}

/* main master lcore loop  */

static void
default_master_lcore_loop(void)
{
	print_stats();

	signal(SIGALRM, on_alarm);
	ualarm(alarm_period,alarm_period);
	//for(;;){
		
	//}
		

}

static int
launch_lcore_thread(__attribute__((unused)) void *dummy)
{
	if(rte_get_master_lcore() == rte_lcore_id()){
		printf("Master lcore " GREEN "%u" RESET " entering main thread\n", rte_lcore_id());
		default_master_lcore_loop();
	} else {
		printf("worker lcore " GREEN "%u" RESET " entering worker thread\n", rte_lcore_id());
		default_worker_lcore_loop();
	}

	return 0;
}

/* display usage */
static void
l2fwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
		   "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
		   "  --[no-]mac-updating: Enable or disable MAC addresses updating (enabled by default)\n"
		   "  -S slow-mode\n",
	       prgname);
}

static int
parse_slow_mode(const char *q_arg)
{
        char *end = NULL;
        int n;

        /* parse hexadecimal string */
        n = strtoul(q_arg, &end, 10);
        if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
                return 0;
        if (n <= 0)
                return 0;
        if (n > 0)
                return 1;

        return n;
}

static int
l2fwd_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static const char short_options[] =
	"S:"
	"p:"  /* portmask */
	"q:"  /* number of queues */
	"T:"  /* timer period */
	;

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
};

static const struct option lgopts[] = {
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
                /* slow-mode */
                case 'S':
                        slow_mode_enabled = parse_slow_mode(optarg);
                        break;

		/* portmask */
		case 'p':
			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
			if (l2fwd_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			timer_period = timer_secs;
			break;

		/* long options */
		case 0:
			break;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid, last_port;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;
	unsigned int nb_lcores = 0;
	unsigned int nb_mbufs;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid arguments\n");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/* check port mask to possible port mask */
	if (l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
			(1 << nb_ports) - 1);

	/* reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0;
	last_port = 0;

	/*
	 * Each logical core is assigned a dedicated TX queue on each port.
	 */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		if (nb_ports_in_mask % 2) {
			l2fwd_dst_ports[portid] = last_port;
			l2fwd_dst_ports[last_port] = portid;
		}
		else
			last_port = portid;

		nb_ports_in_mask++;
	}
	if (nb_ports_in_mask % 2) {
		printf("Notice: odd number of ports in portmask.\n");
		l2fwd_dst_ports[last_port] = last_port;
	}

	printf("Master core is: %u \n", rte_get_master_lcore());

	rx_lcore_id = 2; //min index of core assigned to processing thread
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       l2fwd_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
	}

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);

	/* create the mbuf pool */
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);
		rte_eth_dev_info_get(portid, &dev_info);
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);

		rte_eth_macaddr_get(portid,&port_eth_addr[portid]);

		/* init one RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     l2fwd_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, portid);

		/* init one TX queue on each port */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);

		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			"Cannot set error callback for tx buffer on port %u\n",
				 portid);

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("done: \n");

		rte_eth_promiscuous_enable(portid);

    /* Add the callbacks for RX and TX.*/
    //rte_eth_add_rx_callback(portid, 0, add_timestamps, NULL);
    rte_eth_add_tx_callback(portid, 0, calc_latency, NULL);

		printf(GREEN "Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n" RESET,
				portid,
				port_eth_addr[portid].addr_bytes[0],
				port_eth_addr[portid].addr_bytes[1],
				port_eth_addr[portid].addr_bytes[2],
				port_eth_addr[portid].addr_bytes[3],
				port_eth_addr[portid].addr_bytes[4],
				port_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(l2fwd_enabled_port_mask);

	ret = 0;

	/*	set default IPs 	*/	

	memcpy(&port_ip_addr[0], &(uint8_t[]){0,0,0,0}, 4);
	memcpy(&port_ip_addr[1], &(uint8_t[]){0,0,0,0}, 4);

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(launch_lcore_thread, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) { //while lcore is busy w/ job
			ret = -1;
			break;
		}
	}

	//printf("Calling master loop\n");
	//default_master_lcore_loop();

	RTE_ETH_FOREACH_DEV(portid) {
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return ret;
}
