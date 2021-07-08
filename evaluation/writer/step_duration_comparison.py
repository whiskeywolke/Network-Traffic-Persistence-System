import sys
from matplotlib.transforms import Bbox
import numpy as np
import matplotlib.pyplot as plt
from numpy.lib.function_base import median as npmedian


def main(filename):

    packetcount = 0

    if('dirB' in filename):
        packetcount = 107555567
    if('dirA' in filename):
        packetcount = 27013768 
    if('own' in filename):
        packetcount = 1031565 

    dataset = np.loadtxt(filename, delimiter=';', skiprows=1)
    labels = open(filename).readlines()[0].rstrip().split(';')
    labels = ['read', 'convert','sort', 'compress','aggregate', 'write', 'total']
    

    np.set_printoptions(precision=4)
    fig1, ax1 = plt.subplots()
    ax1.set_xlabel('nanoseconds')
    ax1.set_ylabel('percentiles')

    datadict = {}

    for i in range(7):
        datadict[labels[i].split(' ')[0]] = dataset[:,i]
        

    fig3, ax3 = plt.subplots()
    ax3.set_title("Processing time per packet per processing step")
    ax3.boxplot([el/packetcount for el in datadict.values()], showfliers=True)
    ax3.set_xticklabels(datadict.keys())
    ax3.set_ylabel('nanoseconds')

   
    ax3.plot()

    plt.savefig("step_cumulative_runtime.png")

main(sys.argv[1])
