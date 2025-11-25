#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static void die(const char *msg)
{
	perror(msg);
	exit(1);
}

static uint16_t ip_checksum(void *vdata, size_t len)
{
	uint32_t acc = 0;
	uint16_t *data = vdata;
	for (size_t i = 0; i + 1 < len; i += 2)
		acc += data[i / 2];
	if (len & 1)
		acc += ((uint8_t *)vdata)[len - 1];
	while (acc >> 16)
		acc = (acc & 0xffff) + (acc >> 16);
	return htons((uint16_t)(~acc));
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s <iface> <dst-mac>\n", argv[0]);
		fprintf(stderr, "  dst-mac format: aa:bb:cc:dd:ee:ff\n");
		return 1;
	}

	const char *ifname = argv[1];
	unsigned char dst_mac[ETH_ALEN];
	if (sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &dst_mac[0], &dst_mac[1], &dst_mac[2],
		   &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
		fprintf(stderr, "invalid dst-mac\n");
		return 1;
	}

	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0)
		die("socket");

	struct ifreq ifr = {};
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
		die("SIOCGIFINDEX");
	int ifindex = ifr.ifr_ifindex;
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
		die("SIOCGIFHWADDR");
	unsigned char *src_mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

	unsigned char payload[] = {0x01, 0x02, 0x03, 0x04};
	const int inner_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(payload);
	const int outer_ip_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 8 + inner_len;
	const int frame_len = sizeof(struct ethhdr) + outer_ip_len;
	unsigned char buf[1500];

	if (frame_len > (int)sizeof(buf)) {
		fprintf(stderr, "frame too large\n");
		return 1;
	}
	memset(buf, 0, sizeof(buf));

	struct ethhdr *eth = (struct ethhdr *)buf;
	memcpy(eth->h_dest, dst_mac, ETH_ALEN);
	memcpy(eth->h_source, src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);

	struct iphdr *ip = (struct iphdr *)(eth + 1);
	ip->version = 4;
	ip->ihl = 5;
	ip->tot_len = htons(outer_ip_len);
	ip->protocol = IPPROTO_UDP;
	ip->ttl = 64;
	ip->saddr = inet_addr("203.0.113.1");
	ip->daddr = inet_addr("203.0.113.2");
	ip->check = ip_checksum(ip, ip->ihl * 4);

	struct udphdr *udp = (struct udphdr *)((unsigned char *)ip + sizeof(struct iphdr));
	udp->source = htons(12345);
	udp->dest = htons(2152);
	udp->len = htons(sizeof(struct udphdr) + 8 + inner_len);
	udp->check = 0; /* acceptable for IPv4 */

	unsigned char *gtp = (unsigned char *)(udp + 1);
	gtp[0] = 0x30; /* Flags */
	gtp[1] = 0xff; /* TPDU */
	gtp[2] = 0x00; /* length msb */
	gtp[3] = sizeof(payload); /* length lsb */
	gtp[4] = 0x00;
	gtp[5] = 0x00;
	gtp[6] = 0x00;
	gtp[7] = 0x01; /* TEID = 1 */

	struct iphdr *inner_ip = (struct iphdr *)(gtp + 8);
	inner_ip->version = 4;
	inner_ip->ihl = 5;
	inner_ip->tot_len = htons(inner_len);
	inner_ip->protocol = IPPROTO_UDP;
	inner_ip->ttl = 63;
	inner_ip->saddr = inet_addr("10.0.0.1");
	inner_ip->daddr = inet_addr("8.8.8.8");
	inner_ip->check = ip_checksum(inner_ip, inner_ip->ihl * 4);

	struct udphdr *inner_udp = (struct udphdr *)((unsigned char *)inner_ip + sizeof(struct iphdr));
	inner_udp->source = htons(5555);
	inner_udp->dest = htons(6666);
	inner_udp->len = htons(sizeof(struct udphdr) + sizeof(payload));
	inner_udp->check = 0;

	memcpy(inner_udp + 1, payload, sizeof(payload));

	struct sockaddr_ll saddr = {
		.sll_family = AF_PACKET,
		.sll_ifindex = ifindex,
		.sll_halen = ETH_ALEN,
	};
	memcpy(saddr.sll_addr, dst_mac, ETH_ALEN);

	ssize_t sent = sendto(sock, buf, frame_len, 0, (struct sockaddr *)&saddr, sizeof(saddr));
	if (sent < 0)
		die("sendto");

	printf("sent %zd bytes on %s (GTP-U TEID=1 payload=4B)\n", sent, ifname);
	return 0;
}
