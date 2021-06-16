import sys
from matplotlib.transforms import Bbox
import numpy as np
import matplotlib.pyplot as plt
from numpy.lib.function_base import median


def main():
    files = [
    'no_query/reader_evaluation.csv',
    './simple_query/reader_evaluation_simple.csv',
    './complex_query/reader_evaluation_complex.csv',
    './very_complex_query/reader_evaluation_vcomplex.csv']
    names = ['no query', 'simple', 'complex','very complex']

#    dataset = np.loadtxt(files[0], delimiter=';', skiprows=1, usecols=0)


    datadict = {}
    for i in range(len(files)):
        dataset = np.loadtxt(files[i], delimiter=';', skiprows=1, usecols=0)
        datadict[names[i]] = dataset

    np.set_printoptions(precision=4)

    fig1, ax1 = plt.subplots()
    ax1.set_title("Query Runtime Analysis")
    ax1.boxplot(datadict.values())
    ax1.set_xticklabels(datadict.keys())

    np.set_printoptions(precision=4)
    #text = "min = " + str(min(dataset[:,i])) + "\nmax = " + str(max(dataset[:,i])) + "\nmean = " + str(np.round(np.average(dataset[:,i]), 4)) + "\nmedian = " + str(np.round(median(dataset[:,i]),4))
    #box = dict(boxstyle='round', facecolor='white', alpha=0.5)
    #ax1.text(0.03,0.8,text, transform=ax1.transAxes, bbox=box)
    plt.savefig("Query Runtime Analysis.png")






main()
