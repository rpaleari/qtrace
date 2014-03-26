"""
Copyright 2014, Roberto Paleari (@rpaleari)

Fuzzer driver for Microsoft Windows guests.
Communication between the host and the guest is based on XMLRPC.
"""

import argparse
import commonrpc
import logging
import xmlrpclib
import SimpleXMLRPCServer

import syscall_pb2

# Add custom xmlrpclib dispatchers for QTrace objects
commonrpc.customize(xmlrpclib)

DEFAULT_RPC_PORT = 31340

def execute_trace(trace):
    print trace

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(formatter_class = 
                                     argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-p", "--port", default = DEFAULT_RPC_PORT,
                        help = "RPC server port", type = int)
    parser.add_argument("-v", "--loglevel",  help = "set log level", 
                        default = "INFO",
                        choices = ["CRITICAL", "DEBUG", "ERROR", 
                                   "WARNING", "INFO"])
    args = parser.parse_args()

    # Initialize logging subsystem
    numeric_loglevel = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_loglevel, int):
        raise ValueError('Invalid log level: %s' % args.loglevel)
    logging.basicConfig(format = '[%(asctime)s] %(levelname)s : %(message)s',
                        level = numeric_loglevel)

    # Start the RPC server
    server = SimpleXMLRPCServer.SimpleXMLRPCServer(("", args.port), 
                                                   logRequests = False, 
                                                   allow_none = True)
    server.register_function(execute_trace, 'executeTrace')

    logging.info("Waiting for connections on port %d...", args.port)
    server.serve_forever()

if __name__ == "__main__":
    main()


