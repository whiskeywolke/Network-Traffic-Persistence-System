#!/bin/bash

WRITEDIR="/home/ubuntu/testfiles/evaluation/"

TESTFILE="/home/ubuntu/testfiles/test4.pcap"
#TESTFILE="/home/ubuntu/testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap"

OUTFILE="evaluation.csv"

HEADER="reading_duration;conversion_duration;sorting_duration;compression_duration;aggregation_duration;writing_duration;total_duration;packet_handling_time;packets_per_second;packet_count;total_file_size;bytes_packet;file_count"

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


