# ps -o user,pid,ppid,vsz,rss,state,ucmd -ef --forest | grep server

import httplib
import ssl
import math
import optparse
import random
import socket
import sys
import time
from threading import Thread

class RequesterThread(Thread):
    def __init__(self, host, port, uri, duration, identifier):
        Thread.__init__(self)
        self.host = host
        self.port = port
        self.uri = uri
        self.duration = duration
        self.identifier = identifier
        
    def run(self):
        result = True
        error = ''
        start_time = time.time()

        conn = httplib.HTTPSConnection(self.host, self.port, context=ssl._create_unverified_context())

        num = 0
        while result and ((time.time() - start_time) < self.duration):
            buflen = 0
            try:
                exp_start = time.time()
                conn.request("GET", self.uri, None, {'X-Stress':'%d-%d' % (self.identifier,num)})
                num += 1
                resp = conn.getresponse()
                if int(resp.status) != 200:
                    error = '(Status = %d)' % (resp.status)
                    result = False
                else:
                    givenlength = resp.getheader('content-length')
                    mimetype = resp.getheader('content-type')
                    if not givenlength:
                        error = '(No content-length given)'
                        result = False
                    elif not givenlength.isdigit():
                        error = '(Invalid content-length)'
                        result = False
                    else:
                        givenlength = int(givenlength)

                        buflen = 0
                        while True:
                            buf = resp.read(65000)
                            if len(buf) > 0:
                                buflen += len(buf)
                            else:
                                error = "(Expected %d bytes got %d bytes)" % (givenlength,buflen)
                                result = False
                                break
                            if buflen >= givenlength:
                                break

            except:
                error = sys.exc_info()[1]
                result = False
            elapsedtime = time.time() - exp_start
            if buflen == 0 or elapsedtime == 0:
                throughput = 0.00
            else:
                throughput = (8*buflen / elapsedtime)
            if throughput >  1000000:
                throughput = throughput / 1000000
                units = "Mbps"
            else:
                throughput = throughput / 1000
                units = "Kbps"
            print " Thread %d finished download %d in %5.2f sec, throughput = %6.2f (%s)" % (self.identifier,num-1,elapsedtime,throughput,units),
            if result:
                print "[OK]"
            else:
                print "[FAILED]", error
            sys.stdout.flush()

class WorkloadGenerator:
    def __init__(self, hostname, port, uri, num_threads, duration):
        self.threads = []
        self.hostname = hostname
        self.port = 80
        self.uri = uri
        identifier = 0
        for i in range(num_threads):
            self.threads.append(RequesterThread(hostname, port, uri, duration, identifier))
            identifier += 1
        self.duration = duration
        
    def launch_requesters(self):
        for thread in self.threads:
            time.sleep(0.1)
            thread.start()
        time.sleep(self.duration)
        print "Waiting for thread termination ..."
        for thread in self.threads:
            thread.join()
            
if __name__ == "__main__":
    parser = optparse.OptionParser(usage="%prog hostname[:port]/file -t [threads] -d [duration]", version="%prog 1.0")
    parser.add_option("-t", "--threads", dest="threads", type="int", default=1,
                      help= "number of busy threads to test")
    parser.add_option("-d", "--duration", dest="duration", type="int", default=30,
                      help= "duration of test")
    (options, args) = parser.parse_args()

    # check for host:port/file
    if len(args) < 1:
        parser.error("You must specifiy a host:port/file argument.")
    hostparts = args[0].split('/')
    portparts = hostparts[0].split(':')
    hostname = portparts[0]
    uri = '/' + '/'.join(hostparts[1:])
    port = 80
        
    if (len(portparts) > 1):
        port = int(portparts[1])
                
    print "Host: %s, Port: %d, URI: %s" % (hostname, port, uri)
    print "Number of concurrently busy threads: %d" % (int(options.threads))
    print "Duration of test:                  : %d sec" % (int(options.duration))
    print "--------------------------------------------------------"
        
    # launch generators
    generator = WorkloadGenerator(hostname, port, uri, int(options.threads),
                                  int(options.duration))
    generator.launch_requesters()
