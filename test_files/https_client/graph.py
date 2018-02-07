import prettyplotlib as ppl
from cycler import cycler
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
    bytes_downloaded = 0
    if '-f' in myargs:
        fname = myargs['-f']
    if '-o' in myargs: #outputfilename for the png
        tGraph = myargs['-o']
        bGraph = myargs['-o']
    if '-b' in myargs:
        bytes_downloaded = 1

    fig, ax = plt.subplots(1)
    df = pd.read_csv(open(fname,'rb'),sep=',').groupby('target')
    plt.rc('lines', linewidth=4)
    plt.rc('axes', prop_cycle=(cycler('color', ['r', 'g'])))
    for name,target in df:
        split = target.groupby('ssl');
        if name == "www.phoenixteam.net":
            name = "(remote)"
        else:
            name = "(local)"
        for name2,t in split:
            if bytes_downloaded == 0:
                data = t.groupby("numThreads")["timeElapsed"].mean()
            else:
                data = t.groupby("amountDownloaded")["timeElapsed"].mean()
            params = '-'
            if name2 == 0:
                name2 = "SSA "
            else:
                name2 = "OpenSSL "
                params = '--'
            ppl.plot(data,params ,label=name2+name)
    if bytes_downloaded == 0:
        ppl.legend(ax, loc ="upper left")
        plt.ylabel('Time Elapsed')
        plt.xlabel('Number of Processes')
        plt.title('Time Elapsed Workload')
        fig.savefig(tGraph)
    else:
        ppl.legend(ax, loc ="upper left")
        plt.ylabel('Time Elapsed')
        plt.xlabel('Number of Bytes Downloaded')
        plt.title('Time Elapsed Workload')
        fig.savefig(bGraph)
