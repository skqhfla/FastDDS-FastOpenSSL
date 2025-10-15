#!/bin/bash

FILE_LIST=(`ls`)

for FILE in ${FILE_LIST[@]}; do
    if [ "${FILE}"=="AESGCMGMAC*" ]; then
        PRE=`echo ${FILE} | cut -d "_" -f1`
        POST=`echo ${FILE} | cut -d "_" -f2`
        RES="${PRE}FAST_${POST}"
        cp ${FILE} ${RES}
    fi
done

