#!/bin/bash -norc
./template/rbibtex $1
sed 's/ USENIX Association\.//' < $1.bbl | \
sed '/\. USENIX/{N;s/USENIX[\n]*[ ]*Association\.//}' | \
sed 's/\. ACM\.//;s/\. IEEE\.//' | \
sed '/\. ACM/{N;s/ACM[\n]*[ ]*SIGOPS\.//}' | \
sed '/\. ACM/{N;s/ACM[\n]*[ ]*Press[,\.]//}' | \
sed '/\. Association/{N;s/Association[\n]*[ ]*for Computing Machinery SIGOPS\.//}' | \
sed '/\. IEEE/{N;s/IEEE[\n]*[ ]*Computer Society\.//}' | \
sed '/ Technical/{N;s/Technical[\n]*[ ]*Report/Tech. Rep./}' | \
sed 's/\.sourceforge\.net/\.sf\.net/g' | \
sed 's/Proceedings/Proc\./g' | \
sed 's/\ pages/\ pp./g' | \
sed 's/Conference/Conf\./g' | \
sed '/\ [0-9][0-9][0-9][0-9])/{N;s/\ ([A-Z][A-Z]*[\n]*[ ]*[0-9][0-9][0-9][0-9])//}' | \
sed '/\ .[0-9][0-9])/{N;s/\ ([A-Z][A-Z]*[\n]*[ ]*.[0-9][0-9])//}' | \
sed '/^\\newblock (/d' > $1.bbl.tmp
mv $1.bbl.tmp $1.bbl
