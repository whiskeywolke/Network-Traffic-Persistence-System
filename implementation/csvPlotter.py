import sys
import numpy as np
import matplotlib.pyplot as plt


def main(filename):
    print(filename)
    dataset = np.loadtxt(filename, delimiter=',', skiprows=1)
    labels = open(filename).readlines()[0].rstrip().split(',')

    print(labels)
    plt.plot(dataset[:,0], dataset[:,1])
    plt.xlabel(labels[0])
    plt.ylabel(labels[1])
    plt.show()


main(sys.argv[1])