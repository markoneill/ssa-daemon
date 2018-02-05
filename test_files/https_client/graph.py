import prettyplotlib as ppl
import numpy as np
import csv
# prettyplotlib imports
import matplotlib.pyplot as plt
import matplotlib as mpl
from prettyplotlib import brewer2mpl
import pandas as pd


def getopts(argv):
    opts = {}  # Empty dictionary to store key-value pairs.
    while argv:  # While there are arguments left to parse...
        if argv[0][0] == '-':  # Found a "-name value" pair.
            opts[argv[0]] = argv[1]  # Add key and value to the dictionary.
        argv = argv[1:]  # Reduce the argument list by copying it starting from index 1.
    return opts

if __name__ == '__main__':
    from sys import argv
    myargs = getopts(argv)
    fname = 'stats.csv'
    tGraph = 'ThreadsElapsedTime.png'
    bGraph = 'BytesDownloaded.png'
    if '-f' in myargs:
        fname = myargs['-f']
    if '-t' in myargs: #outputfilename for the png
        tGraph = myargs['-t']
    if '-b' in myargs:
        bGraph = myargs['-b']

    fig, ax = plt.subplots(1)
    df = pd.read_csv(open(fname,'rb'),sep=',').groupby('ssl')
    sslData = df.get_group(1).groupby("numThreads")["timeElapsed"].mean()
    ssaData = df.get_group(0).groupby("numThreads")["timeElapsed"].mean()

    ppl.plot(ssaData,'b-', label="ssaData")
    ppl.plot(sslData,'r--', label="opensslData")
    ppl.legend(ax, loc ="upper left")
    plt.ylabel('Time Elapsed')
    plt.xlabel('Number of Processes')
    plt.title('Time Elapsed Workload')

    fig.savefig(tGraph)
    fig, ax = plt.subplots(1)

    sslData = df.get_group(1).groupby("amountDownloaded")["timeElapsed"].mean()
    ssaData = df.get_group(0).groupby("amountDownloaded")["timeElapsed"].mean()

    ppl.plot(ssaData,'b-', label="ssaData")
    ppl.plot(sslData,'r--', label="opensslData")
    ppl.legend(ax, loc ="upper left")
    plt.ylabel('Time Elapsed')
    plt.xlabel('Number of Bytes Downloaded')
    plt.title('Time Elapsed Workload')
    fig.savefig(bGraph)

