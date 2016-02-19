#!/bin/bash
set -x
set -e

wget http://hgdownload.cse.ucsc.edu/goldenPath/hg19/encodeDCC/wgEncodeUwRepliSeq/wgEncodeUwRepliSeqK562G1AlnRep1.bam
samtools sort -m1M wgEncodeUwRepliSeqK562G1AlnRep1.bam wgEncodeUwRepliSeqK562G1AlnRep1.sorted.bam
