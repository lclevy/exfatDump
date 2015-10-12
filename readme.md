
# ExFAT dump #

## Introduction ##

*exfat_dump.py* is an experimental tool for forensic analysis of the ExFAT filesystem.
User interface is inspired by [The Sleuth Kit](http://www.sleuthkit.org/sleuthkit/ "The Sleuth Kit") commands.

Features:

- displays partitions table (**mmls**, from MBR)
- displays filesystem information (**fsstat**, from VBR and root directory)
- lists (recursively, **-r** option) files and directory entries
- displays deleted directory entries (with debug level 2, **-d 2**) 
- displays Modification, Creation/Birth and Access timestamps (**-l** option)
- displays first cluster number and 'next cluster method' (FAT chaining -fat- or contiguous -nfc*-)
- file content extraction (**icat** command)
- optionally computes SHA1 of extracted data (**-h** option)
- computes bitmap statistics (like chkdsk, with **fsstat** command)
- can display bitmap content (**-d** 2)
- can display clusters list for a given file or directory (**istat**)

*nfc = NoFatChaining 

Requirements: Python 2.7.x only.

## Reference document ##

Reverse Engineering the Microsoft exFAT File System, by Robert Shullich, 2009, SANS Institute InfoSec Reading Room: [http://reverse-engineering-microsoft-exfat-file-system-33274-1.pdf](http://reverse-engineering-microsoft-exfat-file-system-33274-1.pdf)

## Intellectual property notes ##


- FAT and exFAT is protected by Microsoft patents
- This experimental code is released under GPL license

## Usage ##

**mmls** displays partitions information from the MBR:

    >python exfat_dump.py mmls exfat12.001
    MBR, Partition table:
    bootable type      start        end       size
        0x80 0x07 0000000051 0000060800 0000060749 (ExFAT/NTFS)

**fsstat** displays filesystem information, mainly using VBR content. Volume label comes from root directory and free/allocated cluster from Bitmap. Option **-o** is used to explicit which partition to use, via its starting sector.
If ommited, the first partition with type 7 is used.

    >python exfat_dump.py fsstat -o 51 exfat12.001
    FILE SYSTEM INFORMATION
    --------------------------------------------
    File System Type: EXFAT
    Sector size: 512 bytes
    Cluster size: 4 sectors
    FAT size: 120 sectors
    Data area size: 15123 clusters
    Volume label: EOS_DIGITAL
    VBR#1 0x00006600-0x00007e00 (sectors 51-63)
    VBR#2 0x00007e00-0x00009600 (sectors 63-75)
    FAT#1 0x00016600-0x00025600 (sectors 179-299)
    dataArea 0x00026600-0x01dafe00 (sectors 307-60799, clusters 2-15125)
    rootDir at 0x28600 (sector 323, cluster 6)
    
    Directories: 2 (6 Kb) Files: 23 (26590 Kb)
    Rootdir: 3 clusters (6 Kb)
    Bitmap= 15123 available clusters (30246 Kb), 1811 free clusters (3622 Kb), 13312 allocated clusters (26624 Kb)

**fls** command is used to list directory entries. First column is modification timestamp, then attributes, first cluster number (0 means irrelevant), content size and entry name. 
In the following example, the file *adencrypt.exe* starts at cluster #8, its size is 231936 bytes.

    >python exfat_dump.py fls exfat12.001
    2012/08/23 22:13:00:000 a----       8  231936 /adencrypt_gui.exe
    2012/08/23 22:12:52:000 a----     122    7680 /adfs_globals.dll
    2012/08/23 22:12:50:000 a----     126   70144 /ADIsoDLL.dll
    2012/08/23 22:13:06:000 a----     161  377856 /adshattrdefs.dll
    2015/09/17 21:25:44:183 -d---    8004    2048 /empty_dir
    2015/09/17 21:25:36:000 a----    6608      12 /new_file.txt
    2012/03/14 19:54:44:000 a----    8005   31744 /da7zip.dll
    2014/11/28 17:46:50:000 a----    1189 12309315 /volatility_2.4.win.standalone.zip
    2015/02/16 11:26:34:000 -d---       7    4096 /langs
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (5) - Copie.txt
    2011/01/20 19:15:10:000 a----    8510  946176 /cximage.dll
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (4).txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (4) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (6) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (7) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (8) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (9) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (10) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (11) - Copie.txt
    2014/12/10 13:31:24:000 a----    8021  407856 /NEWS.txt
    2013/03/13 15:04:48:000 a----    8973 2481152 /perl516.dll
    2013/12/17 10:44:38:000 a----     400 1613956 /CSIRT_setting_up_guide_ENISA-FR.pdf
    2015/09/20 20:35:54:000 a----   10185 8640336 /Andriller_v2.5.0.2_Setup.exe

Option **-r** is used to list recursively directories:

	>python exfat_dump.py fls -r exfat12.001
    2012/08/23 22:13:00:000 a----       8  231936 /adencrypt_gui.exe
    2012/08/23 22:12:52:000 a----     122    7680 /adfs_globals.dll
    2012/08/23 22:12:50:000 a----     126   70144 /ADIsoDLL.dll
    2012/08/23 22:13:06:000 a----     161  377856 /adshattrdefs.dll
    2015/09/17 21:25:44:183 -d---    8004    2048 /empty_dir
    2015/09/17 21:25:36:000 a----    6608      12 /new_file.txt
    2012/03/14 19:54:44:000 a----    8005   31744 /da7zip.dll
    2014/11/28 17:46:50:000 a----    1189 12309315 /volatility_2.4.win.standalone.zip
    2015/02/16 11:26:34:000 -d---       7    4096 /langs
    2012/08/20 22:41:04:000 a----     346    6144 /langs/chs_adencrypt.dll
    2012/08/20 22:41:04:000 a----     349  104448 /langs/chs_adshattrdefs.dll
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (5) - Copie.txt
    2011/01/20 19:15:10:000 a----    8510  946176 /cximage.dll
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (4).txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (4) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (6) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (7) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (8) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (9) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (10) - Copie.txt
    2015/09/18 10:49:12:000 a----       0       0 /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (11) - Copie.txt
    2014/12/10 13:31:24:000 a----    8021  407856 /NEWS.txt
    2013/03/13 15:04:48:000 a----    8973 2481152 /perl516.dll
    2013/12/17 10:44:38:000 a----     400 1613956 /CSIRT_setting_up_guide_ENISA-FR.pdf
    2015/09/20 20:35:54:000 a----   10185 8640336 /Andriller_v2.5.0.2_Setup.exe

With option **-l**, a lot more details can be displayed, (a)ccess and creation/(b)irth timestamps, secondary count (sc) value and cluster list method (FAT or NoFastChain -nfc-):

     >python exfat_dump.py fls -l exfat12.001
     i=      8 l= 231936 a---- m=2012/08/23 22:13:00:000 a=2015/09/17 21:24:50:000 b=2015/09/17 21:24:50:104 sc=3 nfc /adencrypt_gui.exe
     i=    122 l=   7680 a---- m=2012/08/23 22:12:52:000 a=2015/09/17 21:25:06:000 b=2015/09/17 21:25:06:039 sc=3 nfc /adfs_globals.dll
     i=    126 l=  70144 a---- m=2012/08/23 22:12:50:000 a=2015/09/17 21:25:06:000 b=2015/09/17 21:25:06:086 sc=2 nfc /ADIsoDLL.dll
     i=    161 l= 377856 a---- m=2012/08/23 22:13:06:000 a=2015/09/17 21:25:06:000 b=2015/09/17 21:25:06:139 sc=3 nfc /adshattrdefs.dll
     i=   8004 l=   2048 -d--- m=2015/09/17 21:25:44:183 a=2015/09/17 21:25:44:000 b=2015/09/17 21:25:44:183 sc=2 nfc /empty_dir
     i=   6608 l=     12 a---- m=2015/09/17 21:25:36:000 a=2015/09/17 21:25:36:000 b=2015/09/17 21:25:22:054 sc=2 nfc /new_file.txt
     i=   8005 l=  31744 a---- m=2012/03/14 19:54:44:000 a=2015/09/18 15:06:58:000 b=2015/09/18 15:06:58:032 sc=2 nfc /da7zip.dll
     i=   1189 l=12309315 a---- m=2014/11/28 17:46:50:000 a=2015/10/02 17:30:40:000 b=2015/10/02 17:30:40:080 sc=4 fat /volatility_2.4.win.standalone.zip
     i=      7 l=   4096 -d--- m=2015/02/16 11:26:34:000 a=2015/09/17 21:24:54:000 b=2015/09/17 21:24:54:147 sc=2 fat /langs
     i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:50:000 b=2015/09/18 15:07:50:115 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (5) - Copie.txt
     i=   8510 l= 946176 a---- m=2011/01/20 19:15:10:000 a=2015/09/18 15:06:58:000 b=2015/09/18 15:06:58:143 sc=2 nfc /cximage.dll
     i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:38:000 b=2015/09/18 15:07:38:093 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (4).txt
     i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:48:000 b=2015/09/18 15:07:48:101 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (4) - Copie.txt
     i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:52:000 b=2015/09/18 15:07:52:161 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (6) - Copie.txt
     i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:54:000 b=2015/09/18 15:07:54:136 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (7) - Copie.txt
     i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:56:000 b=2015/09/18 15:07:56:112 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (8) - Copie.txt
     i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:58:000 b=2015/09/18 15:07:58:087 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (9) - Copie.txt
     i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:08:00:000 b=2015/09/18 15:08:00:062 sc=9 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (10) - Copie.txt
     i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:08:02:000 b=2015/09/18 15:08:02:038 sc=9 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (11) - Copie.txt
     i=   8021 l= 407856 a---- m=2014/12/10 13:31:24:000 a=2015/09/22 14:52:50:000 b=2015/09/22 14:52:50:160 sc=2 nfc /NEWS.txt
     i=   8973 l=2481152 a---- m=2013/03/13 15:04:48:000 a=2015/09/22 14:53:32:000 b=2015/09/22 14:53:32:107 sc=2 nfc /perl516.dll
     i=    400 l=1613956 a---- m=2013/12/17 10:44:38:000 a=2015/09/25 14:24:36:000 b=2015/09/25 14:24:36:124 sc=4 nfc /CSIRT_setting_up_guide_ENISA-FR.pdf
     i=  10185 l=8640336 a---- m=2015/09/20 20:35:54:000 a=2015/09/25 15:03:46:000 b=2015/09/25 15:03:46:081 sc=3 nfc /Andriller_v2.5.0.2_Setup.exe


With debug level 1 (**-d 1**), MBR, VBR and Bitmap information is shown:

    >python exfat_dump.py fls -l -r -d 1 exfat12.001

    command= fls -o 0 cluster -1 -r True -p False -d 1 -l True -h False
    MBR, Partition table:
    bootable type  startend   size
    0x80 0x07 0000000051 0000060800 0000060749 (ExFAT/NTFS)
    
    FILE SYSTEM INFORMATION
    --------------------------------------------
    File System Type: EXFAT   
    Sector size: 512 bytes
    Cluster size: 4 sectors
    FAT size: 120 sectors
    Data area size: 15123 clusters
    Volume label: EOS_DIGITAL
    VBR#1 0x00006600-0x00007e00 (sectors 51-63)
    VBR#2 0x00007e00-0x00009600 (sectors 63-75)
    FAT#1 0x00016600-0x00025600 (sectors 179-299)
    dataArea 0x00026600-0x01dafe00 (sectors 307-60799, clusters 2-15125)
    rootDir at 0x28600 (sector 323, cluster 6)
    
    Directories: 2 (6 Kb) Files: 23 (26590 Kb)
    Rootdir: 3 clusters (6 Kb)
    Bitmap= 15123 available clusters (30246 Kb), 1811 free clusters (3622 Kb), 13312 allocated clusters (26624 Kb)
    
    0x81:  i=      2 l=   1891 ----- m=                        a=                        b=                        sc=0 nfc /bitmap
    0x82:  i=      3 l=   5836 ----- m=                        a=                        b=                        sc=0 nfc /upcase
    0x85:  i=      8 l= 231936 a---- m=2012/08/23 22:13:00:000 a=2015/09/17 21:24:50:000 b=2015/09/17 21:24:50:104 sc=3 nfc /adencrypt_gui.exe
    0x85:  i=    122 l=   7680 a---- m=2012/08/23 22:12:52:000 a=2015/09/17 21:25:06:000 b=2015/09/17 21:25:06:039 sc=3 nfc /adfs_globals.dll
    0x85:  i=    126 l=  70144 a---- m=2012/08/23 22:12:50:000 a=2015/09/17 21:25:06:000 b=2015/09/17 21:25:06:086 sc=2 nfc /ADIsoDLL.dll
    0x85:  i=    161 l= 377856 a---- m=2012/08/23 22:13:06:000 a=2015/09/17 21:25:06:000 b=2015/09/17 21:25:06:139 sc=3 nfc /adshattrdefs.dll
    0x85:  i=   8004 l=   2048 -d--- m=2015/09/17 21:25:44:183 a=2015/09/17 21:25:44:000 b=2015/09/17 21:25:44:183 sc=2 nfc /empty_dir
    0x85:  i=   6608 l=     12 a---- m=2015/09/17 21:25:36:000 a=2015/09/17 21:25:36:000 b=2015/09/17 21:25:22:054 sc=2 nfc /new_file.txt
    0x85:  i=   8005 l=  31744 a---- m=2012/03/14 19:54:44:000 a=2015/09/18 15:06:58:000 b=2015/09/18 15:06:58:032 sc=2 nfc /da7zip.dll
    0x85:  i=   1189 l=12309315 a---- m=2014/11/28 17:46:50:000 a=2015/10/02 17:30:40:000 b=2015/10/02 17:30:40:080 sc=4 fat /volatility_2.4.win.standalone.zip
    0x85:  i=      7 l=   4096 -d--- m=2015/02/16 11:26:34:000 a=2015/09/17 21:24:54:000 b=2015/09/17 21:24:54:147 sc=2 fat /langs
    0x85:  i=    346 l=   6144 a---- m=2012/08/20 22:41:04:000 a=2015/09/17 21:24:54:000 b=2015/09/17 21:24:54:157 sc=3 nfc /langs/chs_adencrypt.dll
    0x85:  i=    349 l= 104448 a---- m=2012/08/20 22:41:04:000 a=2015/09/17 21:24:54:000 b=2015/09/17 21:24:54:177 sc=3 nfc /langs/chs_adshattrdefs.dll
    0x85:  i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:50:000 b=2015/09/18 15:07:50:115 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (5) - Copie.txt
    0x85:  i=   8510 l= 946176 a---- m=2011/01/20 19:15:10:000 a=2015/09/18 15:06:58:000 b=2015/09/18 15:06:58:143 sc=2 nfc /cximage.dll
    0x85:  i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:38:000 b=2015/09/18 15:07:38:093 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (4).txt
    0x85:  i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:48:000 b=2015/09/18 15:07:48:101 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (4) - Copie.txt
    0x85:  i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:52:000 b=2015/09/18 15:07:52:161 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (6) - Copie.txt
    0x85:  i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:54:000 b=2015/09/18 15:07:54:136 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (7) - Copie.txt
    0x85:  i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:56:000 b=2015/09/18 15:07:56:112 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (8) - Copie.txt
    0x85:  i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:07:58:000 b=2015/09/18 15:07:58:087 sc=8 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (9) - Copie.txt
    0x85:  i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:08:00:000 b=2015/09/18 15:08:00:062 sc=9 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (10) - Copie.txt
    0x85:  i=      0 l=      0 a---- m=2015/09/18 10:49:12:000 a=2015/09/18 15:08:02:000 b=2015/09/18 15:08:02:038 sc=9 fat /nom de fichier vraiment tres tres tres long pour tenir sur plusieurs entrees 0xc1 - Copie (11) - Copie.txt
    0x85:  i=   8021 l= 407856 a---- m=2014/12/10 13:31:24:000 a=2015/09/22 14:52:50:000 b=2015/09/22 14:52:50:160 sc=2 nfc /NEWS.txt
    0x85:  i=   8973 l=2481152 a---- m=2013/03/13 15:04:48:000 a=2015/09/22 14:53:32:000 b=2015/09/22 14:53:32:107 sc=2 nfc /perl516.dll
    0x85:  i=    400 l=1613956 a---- m=2013/12/17 10:44:38:000 a=2015/09/25 14:24:36:000 b=2015/09/25 14:24:36:124 sc=4 nfc /CSIRT_setting_up_guide_ENISA-FR.pdf
    0x85:  i=  10185 l=8640336 a---- m=2015/09/20 20:35:54:000 a=2015/09/25 15:03:46:000 b=2015/09/25 15:03:46:081 sc=3 nfc /Andriller_v2.5.0.2_Setup.exe

Within the output above, the first column is the type of directory record. 0x81 is type for Bitmap record, 0x82 type for Upcase record. 0x85 is normal record. A file entry is often composed of 3 different records: one 0x85 record, one 0xC0 record and one or more 0xC1 records. Each record is 32 bytes long. With debug level 1 (**-d 1**), only 'aggregated entries' starting with 0x85 records are shown, plus 'virtual entries' Bitmap and Upcase. To display all records types (even deleted ones), debug level 2 must be used (**-d 2**).
    
The column with *i=* contains the first cluster number, which can be used by the **istat** or **icat** command. In the following example, we can extract the .zip archive containing the windows standalone version of volatility:

    0x85:  i=   1189 l=12309315 a---- m=2014/11/28 17:46:50:000 a=2015/10/02 17:30:40:000 b=2015/10/02 17:30:40:080 sc=4 fat /volatility_2.4.win.standalone.zip

File at cluster 1189, using the FAT, can be extracted using **icat**

    >python exfat_dump.py icat -h _dev_exfat\exfat12.001 1189
    491c23aea08989cfec62af1a1ae67474d73cbeb1

The **-h** option computes SHA1 value for extracted content

We can compare sha1 value with the one for original file:

    sha1sum c:\Users\lclevy\Downloads\volatility_2.4.win.standalone.zip
    \491c23aea08989cfec62af1a1ae67474d73cbeb1 *c:\\Users\\lclevy\\Downloads\\volatility_2.4.win.standalone.zip

for a file with contiguous clusters (**nfc** flag)

    0x85:  i=   8973 l=2481152 a---- m=2013/03/13 15:04:48:000 a=2015/09/22 14:53:32:000 b=2015/09/22 14:53:32:107 sc=2 nfc /perl516.dll

SHA1 for extracted content is:

    >python exfat_dump.py icat -h exfat12.001 8973
    47f8c6549a641e2f97b121295628b5921f0a6827

sha1 for original file is:

    C:\Users\lclevy\Desktop\afti2>sha1sum "c:\Perl64\bin\perl516.dll"
    \47f8c6549a641e2f97b121295628b5921f0a6827 *c:\\Perl64\\bin\\perl516.dll

With **istat** on file starting at cluster 8 (/adencrypt_gui.exe), here cluster are contiguous:

    >python exfat_dump.py istat exfat12.001 8
    clusterList: [8:121]

It works also on root dir (cluster #6):

    >python exfat_dump.py fsstat exfat12.001
    FILE SYSTEM INFORMATION
    --------------------------------------------
    File System Type: EXFAT
    Sector size: 512 bytes
    Cluster size: 4 sectors
    FAT size: 120 sectors
    Data area size: 15123 clusters
    Volume label: EOS_DIGITAL
    VBR#1 0x00006600-0x00007e00 (sectors 51-63)
    VBR#2 0x00007e00-0x00009600 (sectors 63-75)
    FAT#1 0x00016600-0x00025600 (sectors 179-299)
    dataArea 0x00026600-0x01dafe00 (sectors 307-60799, clusters 2-15125)
    rootDir at 0x28600 (sector 323, cluster 6)
    
    Directories: 2 (6 Kb) Files: 23 (26590 Kb)
    Rootdir: 3 clusters (6 Kb)
    Bitmap= 15123 available clusters (30246 Kb), 1811 free clusters (3622 Kb), 13312 allocated clusters (26624 Kb)

    >python exfat_dump.py istat exfat12.001 6
    clusterList: [6, 8509, 8972]

Using debug level 2 (**-d 2**) and **fls**, we can see all individual records for each directory entries:

    >python exfat_dump.py fls -d 2 _dev_exfat\exfat12.001
    
    command= fls -o 0 cluster -1 -r False -p False -d 2 -l False -h False
    MBR, Partition table:
    bootable type  startend   size
    0x80 0x07 0000000051 0000060800 0000060749 (ExFAT/NTFS)
    
Below *parseDir()* function is in debug mode:

    83:label= E O S _ D I G I T A L 
    81:bitmap 2 1891
    82:upcase entry 3 5836

So we can see above records for volume label (type=0x83), Bitmap and Upcase. Entry names are stored by ExFAT in unicode.

    85:file dir entry, sc=3 2015/09/17 21:24:50:104
    c0:stream ext i=8 l=231936 vl=231936 nl=17 nfc
    c1:filename ext= a d e n c r y p t _ g u i . e 
    c1:filename ext= x e 
       adencrypt_gui.exe

Then, above, records for entry 'adencrypt_gui.exe'. First a record with type 0x85, then one record with type 0xc0, then 2 records of type 0xc1. Here sc=3 means 'record 0x85 is followed by 3 records: 0xc0, 0xc1 and 0xc1'. Directory records are always stored 32 bytes long within directory clusters.

Below we have a record of type 0x41 (deleted 0xc1):  

    ...
    41:filename ext= t t e x t e . t x t (deleted)
    ...

And below a deleted 0x85 entry (record 0x05 followed by 4 deleted records, note sc=4):

    05:file dir entry, sc=4 2015/09/18 15:06:58:059  (deleted)
    40:stream ext i=8021 l=53248 vl=53248 nl=33 nfc  (deleted)
    41:filename ext= b o o s t _ d a t e _ t i m e (deleted)
    41:filename ext= - v c 1 0 0 - m t - 1 _ 4 9 . (deleted)
    41:filename ext= d l l (deleted)
    ...

*l* value is 'content length'. *vl* is 'valid content length', *nl* is 'name length'.

Bitmap content is also displayed with debug level 2:

    Bitmap:
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    00000fcffffffffffffffffffffffffffffffffffffffffffffffffffff070000000000000000000000000000000000
    000000000000000000000000000000000000f8fffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300000000
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000000000000000000000000
    ...

A bit set (1) means 'allocated', a bit cleared (0) means 'free'.



End of document

---------------
