#define _CRT_SECURE_NO_WARNINGS
/*
* webfilter.c -> webfilter.cpp
* (C) 2014, all rights reserved,
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
* DESCRIPTION:
* This is a simple web (HTTP) filter using WinDivert.
*
* It works by intercepting outbound HTTP GET/POST requests and matching
* the URL against a blacklist.  If the URL is matched, we hijack the TCP
* connection, reseting the connection at the server end, and sending a
* blockpage to the browser.
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <queue>

#include "windivert.h"

#define MAXBUF 0xFFFF
#define MAXURL 4096

#define MAX_URL_LEN 100
#define MAX_BLACKLIST_LEN 10000

#define MAX_AUTOMATA_STATES 10000
#define NUM_ALPHABET 42

/*
* URL and blacklist representation.
*/

struct URL {
	char domain[MAX_URL_LEN+1];
};

struct URLlist
{
	int len;
	URL list[MAX_BLACKLIST_LEN];
};

struct AutomataStruct {
	int numState;
	int move[MAX_AUTOMATA_STATES][NUM_ALPHABET]; // delta-function
	int failLink[MAX_AUTOMATA_STATES];
	bool isMalice[MAX_AUTOMATA_STATES];
};

/*
* Pre-fabricated packets.
*/
typedef struct
{
	WINDIVERT_IPHDR  ip;
	WINDIVERT_TCPHDR tcp;
} PACKET, *PPACKET;
typedef struct
{
	PACKET header;
	UINT8 data[];
} DATAPACKET, *PDATAPACKET;

/*
* THe block page contents.
*/
const char block_data[] =
"HTTP/1.1 200 OK\r\n"
"Connection: close\r\n"
"Content-Type: text/html\r\n"
"\r\n"
"<!doctype html>\n"
"<html>\n"
"\t<head>\n"
"\t\t<title>BLOCKED!</title>\n"
"\t</head>\n"
"\t<body>\n"
"\t\t<h1>BLOCKED!</h1>\n"
"\t\t<hr>\n"
"\t\t<p>This URL has been blocked!</p>\n"
"\t</body>\n"
"</html>\n";

/*
* Prototypes
*/
static void PacketInit(PPACKET packet);
static BOOL BlackListMatch(char *domain);
static void BlackListRead(const char *filename);
static BOOL BlackListPayloadMatch(char *data, UINT16 len);
static void ConstructAutomata();
static int char2Idx(char ch);

URLlist blacklist; // due to memory size
AutomataStruct automata;

/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
	HANDLE handle;
	WINDIVERT_ADDRESS addr;
	UINT8 packet[MAXBUF];
	UINT packet_len;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	PVOID payload;
	UINT payload_len;
	PACKET reset0;
	PPACKET reset = &reset0;
	PACKET finish0;
	PPACKET finish = &finish0;
	PDATAPACKET blockpage;
	UINT16 blockpage_len;

	INT16 priority = 404;       // Arbitrary.

								// Read the blacklists.
	if (argc <= 1)
	{
		fprintf(stderr, "usage: %s blacklist.txt\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	// init blacklist, actually not necessary
	blacklist.len = 0;
	// read blacklist
	BlackListRead(argv[1]);
	// pre-processing
	ConstructAutomata();

	printf("blasklist length: %d\n", blacklist.len);
	for (int i = 0; i < blacklist.len; i++)
		printf("%d : %s\n", i + 1, blacklist.list[i].domain);

	// Initialize the pre-frabricated packets:
	blockpage_len = sizeof(DATAPACKET) + sizeof(block_data) - 1;
	blockpage = (PDATAPACKET)malloc(blockpage_len);
	if (blockpage == NULL)
	{
		fprintf(stderr, "error: memory allocation failed\n");
		exit(EXIT_FAILURE);
	}
	PacketInit(&blockpage->header);
	blockpage->header.ip.Length = htons(blockpage_len);
	blockpage->header.tcp.SrcPort = htons(80);
	blockpage->header.tcp.Psh = 1;
	blockpage->header.tcp.Ack = 1;
	memcpy(blockpage->data, block_data, sizeof(block_data) - 1);
	PacketInit(reset);
	reset->tcp.Rst = 1;
	reset->tcp.Ack = 1;
	PacketInit(finish);
	finish->tcp.Fin = 1;
	finish->tcp.Ack = 1;

	// Open the Divert device:
	handle = WinDivertOpen(
		"outbound && "              // Outbound traffic only
		"ip && "                    // Only IPv4 supported
		"tcp.DstPort == 80 && "     // HTTP (port 80) only
		"tcp.PayloadLength > 0",    // TCP data packets only
		WINDIVERT_LAYER_NETWORK, priority, 0
	);
	if (handle == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("OPENED WinDivert\n");

	// Main loop:
	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,
			NULL, NULL, &tcp_header, NULL, &payload, &payload_len) ||
			!BlackListPayloadMatch((char*)payload, (UINT16)payload_len))
		{
			// Packet does not match the blacklist; simply reinject it.
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
			{
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
			continue;
		}

		// The URL matched the blacklist; we block it by hijacking the TCP
		// connection.

		// (1) Send a TCP RST to the server; immediately closing the
		//     connection at the server's end.
		reset->ip.SrcAddr = ip_header->SrcAddr;
		reset->ip.DstAddr = ip_header->DstAddr;
		reset->tcp.SrcPort = tcp_header->SrcPort;
		reset->tcp.DstPort = htons(80);
		reset->tcp.SeqNum = tcp_header->SeqNum;
		reset->tcp.AckNum = tcp_header->AckNum;
		WinDivertHelperCalcChecksums((PVOID)reset, sizeof(PACKET), 0);
		if (!WinDivertSend(handle, (PVOID)reset, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send reset packet (%d)\n",
				GetLastError());
		}

		// (2) Send the blockpage to the browser:
		blockpage->header.ip.SrcAddr = ip_header->DstAddr;
		blockpage->header.ip.DstAddr = ip_header->SrcAddr;
		blockpage->header.tcp.DstPort = tcp_header->SrcPort;
		blockpage->header.tcp.SeqNum = tcp_header->AckNum;
		blockpage->header.tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)blockpage, blockpage_len, 0);
		addr.Direction = !addr.Direction;     // Reverse direction.
		if (!WinDivertSend(handle, (PVOID)blockpage, blockpage_len, &addr,
			NULL))
		{
			fprintf(stderr, "warning: failed to send block page packet (%d)\n",
				GetLastError());
		}

		// (3) Send a TCP FIN to the browser; closing the connection at the 
		//     browser's end.
		finish->ip.SrcAddr = ip_header->DstAddr;
		finish->ip.DstAddr = ip_header->SrcAddr;
		finish->tcp.SrcPort = htons(80);
		finish->tcp.DstPort = tcp_header->SrcPort;
		finish->tcp.SeqNum =
			htonl(ntohl(tcp_header->AckNum) + sizeof(block_data) - 1);
		finish->tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)finish, sizeof(PACKET), 0);
		if (!WinDivertSend(handle, (PVOID)finish, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send finish packet (%d)\n",
				GetLastError());
		}
	}
}

/*
* Initialize a PACKET.
*/
static void PacketInit(PPACKET packet)
{
	memset(packet, 0, sizeof(PACKET));
	packet->ip.Version = 4;
	packet->ip.HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->ip.Length = htons(sizeof(PACKET));
	packet->ip.TTL = 64;
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
* Match a URL against the blacklist.
*/
static BOOL BlackListMatch(char *domain)
{
	int curState = 0;
	for (int i = 0; domain[i] != 0; i++)
	{
		while (curState != 0 && automata.move[curState][char2Idx(domain[i])] == 0)
			curState = automata.failLink[curState];
		curState = automata.move[curState][char2Idx(domain[i])];
	}
	
	if (automata.isMalice[curState])
		return true;

	return false;
}

/*
* Read URLs from a file.
*/
static void BlackListRead(const char *filename)
{
	FILE *fp = fopen(filename, "r");

	if (fp == NULL)
	{
		fprintf(stderr, "error: could not open blacklist file %s\n",
			filename);
		exit(EXIT_FAILURE);
	}
	
	// Read URLs from the file and add them to the blacklist:
	fscanf(fp, "%d", &blacklist.len);

	for (int i = 0; i < blacklist.len; i++)
		fscanf(fp, "%s", blacklist.list[i].domain);

	fclose(fp);
}

/*
* construct automata(Aho-Corasick)
*/
static int char2Idx(char ch)
{
	// Case 1. English alphabet : 0(a) - 25(z)
	if (ch >= 'a' && ch <= 'z')
		return ch - 'a';
	if (ch >= 'A' && ch <= 'Z')
		return ch - 'A';
	// Case 2. digits : 26(0) - 35(9)
	if (ch >= '0' && ch <= '9')
		return ch - '0' + 26;
	// Case 3. special characters
	switch (ch)
	{
	case '-':	return 36;
	case '/':	return 37;
	case '.':	return 38;
	case ':':	return 39;
	case '=':	return 40;
	case '?':	return 41;
	default:	return -1; // should not happen
	}
}

static void ConstructAutomata()
{
	int curState, linkState;
	char *URL;
	std::queue<int> Q;

	// init
	automata.numState = 1;
	for (int i = 0; i<NUM_ALPHABET; i++)
		automata.move[0][i] = 0;
	automata.isMalice[0] = false;

	// construct Trie
	for (int idx = 0; idx<blacklist.len; idx++)
	{
		curState = 0;
		URL = blacklist.list[idx].domain;
		for (int i = 0; URL[i] != 0; i++)
		{
			if (automata.move[curState][char2Idx(URL[i])] == 0)
			{
				for (int j = 0; j<NUM_ALPHABET; j++)
					automata.move[automata.numState][j] = 0;
				automata.isMalice[automata.numState] = false;

				automata.move[curState][char2Idx(URL[i])] = automata.numState;
				automata.numState++;
			}

			curState = automata.move[curState][char2Idx(URL[i])];
		}
		automata.isMalice[curState] = true;
	}

	// construct automata.failLink
	automata.failLink[0] = 0;
	for (int i = 0; i<NUM_ALPHABET; i++)
	{
		if (automata.move[0][i] != 0)
		{
			automata.failLink[automata.move[0][i]] = 0;
			Q.push(automata.move[0][i]);
		}
	}
	while (!Q.empty())
	{
		curState = Q.front(); Q.pop();
		for (int i = 0; i<NUM_ALPHABET; i++)
		{
			if (automata.move[curState][i] != 0)
			{
				linkState = automata.failLink[curState];
				while (linkState != 0 && automata.move[linkState][i] == 0)
					linkState = automata.failLink[linkState];
				automata.failLink[automata.move[curState][i]] = automata.move[linkState][i];

				Q.push(automata.move[curState][i]);
			}
		}
	}
}

/*
* Attempt to parse a URL and match it with the blacklist.
*
* BUG:
* - This function makes several assumptions about HTTP requests, such as:
*      1) The URL will be contained within one packet;
*      2) The HTTP request begins at a packet boundary;
*      3) The Host header immediately follows the GET/POST line.
*   Some browsers, such as Internet Explorer, violate these assumptions
*   and therefore matching will not work.
*/
static BOOL BlackListPayloadMatch(char *data, UINT16 len)
{
	static const char get_str[] = "GET /";
	static const char post_str[] = "POST /";
	static const char http_host_str[] = " HTTP/1.1\r\nHost: ";
	char domain[MAXURL];
	char uri[MAXURL];
	UINT16 i = 0, j;
	BOOL result;
	HANDLE console;

	if (len <= sizeof(post_str) + sizeof(http_host_str))		 return FALSE;
	if (strncmp(data, get_str, sizeof(get_str) - 1) == 0)		 i += sizeof(get_str) - 1;
	else if (strncmp(data, post_str, sizeof(post_str) - 1) == 0) i += sizeof(post_str) - 1;
	else														 return FALSE;

	/* extract URI */
	for (j = 0; i < len && data[i] != ' '; j++, i++)
		uri[j] = data[i];

	uri[j] = '\0';

	if (i + sizeof(http_host_str) - 1 >= len)							  return FALSE;
	if (strncmp(data + i, http_host_str, sizeof(http_host_str) - 1) != 0) return FALSE;

	i += sizeof(http_host_str) - 1;

	/* extract Domain */
	for (j = 0; i < len && data[i] != '\r'; j++, i++)
		domain[j] = data[i];

	if ((i >= len) || (j==0))			return FALSE;
	if (domain[j - 1] == '.' && j==1)	return FALSE; // Nice try...

	domain[j] = '\0';

	printf("Domain(%s), URI(%s): ", domain, uri);

	// Search the blacklist:
	result = BlackListMatch(domain);

	// Print the verdict:
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	if (result)
	{
		SetConsoleTextAttribute(console, FOREGROUND_RED);
		puts("BLOCKED!");
	}
	else
	{
		SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		puts("allowed");
	}
	SetConsoleTextAttribute(console,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

	return result;
}