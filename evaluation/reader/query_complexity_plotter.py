import sys
import os
from matplotlib.transforms import Bbox
import numpy as np
import matplotlib.pyplot as plt
from numpy.lib.function_base import median


def main():
    files = [
    'no_query/reader_evaluation.csv',
    'simple_query/reader_evaluation_simple.csv',
    'complex_query/reader_evaluation_complex.csv',
    'very_complex_query/reader_evaluation_vcomplex.csv']
    names = ['no query', 'simple', 'complex','very complex']

    for folder in [ f.name for f in os.scandir('.') if f.is_dir() ]:
        datadictHandling = {}
        datadictWriting = {}
        datadictTotal = {}
        for i in range(len(files)):
            filename = folder + '/' +files[i]
            dataset = np.loadtxt(filename, delimiter=';', skiprows=1)
            labels = open(filename).readlines()[0].rstrip().split(';')

            datadictHandling[names[i]] = dataset[:,0]
            datadictWriting[names[i]] = dataset[:,1]
            datadictTotal[names[i]] = dataset[:,2]

        np.set_printoptions(precision=4)

        fig1, ax1 = plt.subplots()
        ax1.set_title("Query handling runtime analysis of " + folder + '\n')
        ax1.boxplot(datadictHandling.values(), showfliers=True)
        ax1.set_xticklabels(datadictHandling.keys())
        ax1.set_ylabel('nanoseconds')
        plt.savefig("Query handling runtime analysis of " + folder + ".png")


        fig2, ax2 = plt.subplots()
        ax2.set_title("Query writing runtime analysis of " + folder + '\n')
        ax2.boxplot(datadictWriting.values(), showfliers=True)
        ax2.set_xticklabels(datadictWriting.keys())
        ax2.set_ylabel('nanoseconds')
        plt.savefig("Query writing runtime analysis of " + folder + ".png")


        fig3, ax3 = plt.subplots()
        ax3.set_title("Query total runtime analysis of " + folder + '\n')
        ax3.boxplot(datadictTotal.values(), showfliers=True)
        ax3.set_xticklabels(datadictTotal.keys())
        ax3.set_ylabel('nanoseconds')
        plt.savefig("Query total runtime analysis of " + folder + ".png")



main()
