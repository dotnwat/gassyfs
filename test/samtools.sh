#!/bin/bash
set -x
set -e

DIR=samtools
mkdir $DIR
pushd $DIR

# download sample file
BAMFILE=file.bam
wget -O $BAMFILE http://hgdownload.cse.ucsc.edu/goldenPath/hg19/encodeDCC/wgEncodeUwRepliSeq/wgEncodeUwRepliSeqK562G1AlnRep1.bam

# sort
samtools sort -m1M $BAMFILE ${BAMFILE}.sorted

popd
rm -rf $DIR
