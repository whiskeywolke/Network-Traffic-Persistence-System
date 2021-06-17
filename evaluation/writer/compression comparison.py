import sys
from matplotlib.transforms import Bbox
import numpy as np
import matplotlib.pyplot as plt
from numpy.lib.function_base import median


def main():
    
    dataset1 = np.loadtxt('equinix-nyc.dirB.20180517-134900/writer100x_caida6_7.csv', delimiter=';', skiprows=1, usecols=11)
    dataset2 = np.loadtxt('equinix-nyc.dirA.20180517-125910/writer100x_caida1_6.csv', delimiter=';', skiprows=1, usecols=11)
    dataset3 = np.loadtxt('own_traffic/writer100x_own_traffic.csv', delimiter=';', skiprows=1, usecols=11)
    label = open('own_traffic/writer100x_own_traffic.csv').readlines()[0].rstrip().split(';')[11]

    np.set_printoptions(precision=4)


    fig1, ax1 = plt.subplots()
    ax1.set_title(label + " different datasets")
    ax1.boxplot(dataset1, positions=[1])
    ax1.boxplot(dataset2, positions=[2])
    ax1.boxplot(dataset3, positions=[3])
    
    np.set_printoptions(precision=4)
    text = "caida large dataset = " + str(np.round(np.average(dataset1), 4)) + "\ncaida small dataset = " + str(np.round(np.average(dataset2), 4))  + "\nown traffic = " + str(np.round(np.average(dataset3), 4)) 
    box = dict(boxstyle='round', facecolor='white', alpha=0.5)
    ax1.text(0.54,0.84,text, transform=ax1.transAxes, bbox=box)
    plt.savefig('Compression Comparison.png')




main()
