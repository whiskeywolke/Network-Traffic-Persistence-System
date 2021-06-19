import sys
from matplotlib.transforms import Bbox
import numpy as np
import matplotlib.pyplot as plt
from numpy.lib.function_base import median as npmedian


def main(filename):
    dataset = np.loadtxt(filename, delimiter=';', skiprows=1)
    labels = open(filename).readlines()[0].rstrip().split(';')

    np.set_printoptions(precision=4)

    for i in range(len(labels)):
        column = i
        label = labels[column]
        data = np.sort(dataset[:,i])

        minval = min(data)
        maxval = max(data)
        medval = npmedian(data)
        avgval = np.average(data)

        text = "min = " + str(minval) + "\nmax = " + str(maxval) + "\nmean = " + str(np.round(avgval, 4)) + "\nmedian = " + str(np.round(medval,4))
        
        fig1, ax1 = plt.subplots()
        box = dict(boxstyle='round', facecolor='white', alpha=0.5)

        ax1.text(0.03,0.8,text, transform=ax1.transAxes, bbox=box)

        ax1.step(data, [(i+1)/100 for i in range(len(data))], label='Data', where='post')
        ax1.set_title(label)

        if(column<8):
            ax1.set_xlabel('nanoseconds')
        if(column == 8):
            ax1.set_xlabel('packets')
        if(column == 9):
            ax1.set_xlabel('packets')
        if(column == 10):
            ax1.set_xlabel('bytes')
        if(column == 11):
            ax1.set_xlabel('bytes')
        if(column == 12):
            ax1.set_xlabel('files')

        ax1.set_ylabel('percentiles')

        p50 = np.empty(len(data))
        p50.fill(0.5)

        p25 = np.empty(len(data))
        p25.fill(0.25)

        p75 = np.empty(len(data))
        p75.fill(0.75)

        ax1.plot(data,p50, label='Median', linestyle='dashed',color = '#fb6500')
        ax1.annotate('median', xy = (min(data),0.51), color = '#fb6500')

        ax1.plot(data,p25, label='Median', linestyle='dashed',color = '#ffbb39')
        ax1.annotate('$1^{st}$ quartile', xy = (min(data),0.26), color = '#ffbb39')

        ax1.plot(data,p75, label='Median', linestyle='dashed',color = '#ff7a69')
        ax1.annotate('$3^{rd}$ quartile', xy = (min(data),0.76), color = '#ff7a69')

        plt.savefig(label+"_ecdf.png")

main(sys.argv[1])
