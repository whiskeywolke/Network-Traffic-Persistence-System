#!/bin/bash

WRITEDIR="/home/ubuntu/testfiles/evaluation/"

#SOURCEDIR="/home/ubuntu/testfiles/dir/tempmini" #mini file for scipt testing
#SOURCEDIR="/home/ubuntu/testfiles/dir-1-3" #1.3gb own traffic
SOURCEDIR="/home/ubuntu/testfiles/dir-1-6" #1.6gb
#SOURCEDIR="/home/ubuntu/testfiles/dir-6-7" #6.7gb

SIMPLEQUERY="frame.len > 0 &&  frame.time < Jun 15, 2021 12:00:00"
COMPLEXQUERY="frame.len > 0 && frame.len <= 99999999 && frame.time < Jun 15, 2021 12:00:00 &&  frame.time > Jun 15, 2000 12:00:00"
VERYCOMPLEXQUERY="frame.len > 0 && frame.len <= 99999999 && frame.time < Jun 15, 2021 12:00:00 &&  frame.time > Jun 15, 2000 12:00:00 && port >= 0 && ip.addr != 0.0.0.0"

OUTFILE1="reader_evaluation_simple.csv"
OUTFILE2="reader_evaluation_complex.csv"
OUTFILE3="reader_evaluation_vcomplex.csv"

HEADER="Handling Duration;Writing Duration;Total Duration"

PROGRAMLOCATION="./build/reader/a.out"

echo $HEADER >>$OUTFILE1
echo $HEADER >>$OUTFILE2
echo $HEADER >>$OUTFILE3

for i in $(seq $1); do
  RESULT=$($PROGRAMLOCATION -i $SOURCEDIR -o $WRITEDIR -b -pcap -b -f $SIMPLEQUERY)
  echo $RESULT >>$OUTFILE1
  echo $RESULT
  rm $WRITEDIR*
done

for i in $(seq $1); do
  RESULT=$($PROGRAMLOCATION -i $SOURCEDIR -o $WRITEDIR -b -pcap -b -f $COMPLEXQUERY)
  echo $RESULT >>$OUTFILE2
  echo $RESULT
  rm $WRITEDIR*
done

for i in $(seq $1); do
  RESULT=$($PROGRAMLOCATION -i $SOURCEDIR -o $WRITEDIR -b -pcap -b -f $VERYCOMPLEXQUERY)
  echo $RESULT >>$OUTFILE3
  echo $RESULT
  rm $WRITEDIR*
done
