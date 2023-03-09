# A Lightweight Persistence System for Network Traffic Measurements

This repository holds the implementation as well as the paper I have written as my bachelor thesis for computer science at the university of Vienna.


## What is this Application?

This application is intended to capture and store network traffic at very high rates and to provide a structured query-able interface. 
It offers a 10x higher ingestion rate than specialized SQL-time-series databases do not offer sufficient performance for data center monitoring tasks.
The performance increase is achieved by application of domain specific optimizations.

You can find the report at [BSc-Thesis.pdf](BSc-Thesis.pdf) 


A README file regarding installation and setup is located at implementation/implementation_v3/README.txt
A README file regarding the files used for performance experiments can be foun at evaluation/README.txt
