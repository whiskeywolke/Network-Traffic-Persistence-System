#!/bin/bash

WRITEDIR="/home/ubuntu/testfiles/evaluation/"

TESTFILE="/home/ubuntu/testfiles/test4.pcap"
#TESTFILE="/home/ubuntu/testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap"

OUTFILE="evaluation.csv"

HEADER="Reading Duration;Conversion Duration;Sorting Duration;Compression Duration;Aggregation Duration;Writing Duration;Total Duration;Packet Handling Time;Packets per Second;Packet Count;Total File Size;Bytes per Packet;File Count"

PROGRAMLOCATION="./build/writer/a.out"

echo $HEADER >> $OUTFILE

for i in $(seq $1)
do
	RESULT=$($PROGRAMLOCATION  -f $TESTFILE -o $WRITEDIR -b)
	RESULT+=";"$(ls $WRITEDIR | wc -l)
	echo $RESULT >> $OUTFILE
	echo $RESULT
	sleep .5
	rm /home/ubuntu/testfiles/evaluation/*
done


