# exFAT tool for forensic analysis
# Laurent Clevy, lclevy@free.fr
# under GPL License
# maybe subject to patent pending by Microsoft!
# tested with Python 2.7.9
# reference document: http://reverse-engineering-microsoft-exfat-file-system-33274-1.pdf

import sys
from binascii import unhexlify, hexlify
from struct import unpack
from hashlib import sha1
import array

#well not OO programming, but should be easy. class exFAT

#such constant could be class constant

# MBR constants
SECTOR_SIZE = 512
PARTITION_LIST_OFFSET = 0x1be
NUM_PARTITION = 4
PARTITION_ENTRY_SIZE = 16
VBR_SIZE = 12
SYNC_OFFSET = 0x1fe
SYNC_VALUE = 0x55aa

MBR_BOOT_OFFSET=0
MBR_FSTYPE_OFFSET=4
MBR_LBA_START_OFFSET=8
MBR_LBA_SIZE_OFFSET=12

#instance variables should be (among global variables): f, partition, vbr, globalList and rootDir

# reads MBR and returns partitions list
def readMBR(f):
  mbr = f.read(SECTOR_SIZE)
  if unpack('>H', mbr[SYNC_OFFSET:SYNC_OFFSET+2])[0]!=SYNC_VALUE:
    print 'error: no sync value in MBR'  
    return None
  offset = PARTITION_LIST_OFFSET
  partitions = []
  for i in range(NUM_PARTITION):
    boot = mbr[offset+MBR_BOOT_OFFSET]
    type = mbr[offset+MBR_FSTYPE_OFFSET]
    start = unpack('<L',mbr[offset+MBR_LBA_START_OFFSET:offset+MBR_LBA_START_OFFSET+4])[0]
    size = unpack('<L',mbr[offset+MBR_LBA_SIZE_OFFSET:offset+MBR_LBA_SIZE_OFFSET+4])[0]
  if size!=0: #if size==0, not partition
    partitions.append( [boot, type, start, size] )
  offset = offset+PARTITION_ENTRY_SIZE
  return partitions

PARTITION_TYPE_NTFS_EXFAT=7  

partitionType = { str(PARTITION_TYPE_NTFS_EXFAT):'ExFAT/NTFS', '5':'Extended', '1': 'FAT12', '15':'FAT16', '12':'FAT32', '183':'Linux', '182':'LinuxSwap', '238':'EFI' }
# display partitions information  
def displayMBR( pl ):
  print 'MBR, Partition table:'
  print 'bootable type      start        end       size'
  for p in pl:  
    boot, type, start, size = p
    if '{0}'.format(ord(type)) in partitionType:
      strType = partitionType[ '{0}'.format(ord(type)) ]
    else:
      strType = '??'    
    print '    0x%02x 0x%02x %010d %010d %010d (%s)' % ( ord(boot), ord(type), start, start+size, size, strType )
  print  

#class exFAT functions members should here  
   
# VBR constants    
EXFAT_SIGN_OFFSET=3    
EXFAT_VBR1_OFFSET=0x40
EXFAT_VOLSIZE_OFFSET=0x48
EXFAT_FAT1_OFFSET=0x50
EXFAT_FATSIZE_OFFSET=0x54
EXFAT_DATA_OFFSET=0x58
EXFAT_NB_CLUSTERS=0x5C
EXFAT_ROOT_CLUSTER_OFFSET=0x60
EXFAT_SN_OFFSET=0x64
EXFAT_VERSION_OFFSET=0x68
EXFAT_SECTOR_SIZE_OFFSET=0x6c
EXFAT_CLUSTER_SIZE_OFFSET=0x6d

# reads VBR first sector and returns a dictionnary    
def readVBR( f, offset ):
  vbr = dict()
  f.seek( offset*SECTOR_SIZE )
  vbrData = f.read( VBR_SIZE*SECTOR_SIZE )  
  if unpack('>H', vbrData[SYNC_OFFSET:SYNC_OFFSET+2])[0]!=SYNC_VALUE:
    print 'error: no sync value in VBR'  
    return None
  signature = vbrData[EXFAT_SIGN_OFFSET:EXFAT_SIGN_OFFSET+8]
  if signature!='EXFAT   ':
    print 'error: not ExFAT'
    return None
  vbr[ 'signature' ] = signature  
  vbr1 = unpack('<Q',vbrData[EXFAT_VBR1_OFFSET:EXFAT_VBR1_OFFSET+8])[0]
  vbr[ 'vbr1Offset' ] = vbr1
  if vbr1!=offset:
    print 'error: vbr1 address'
    return None
  volSize = unpack('<Q', vbrData[EXFAT_VOLSIZE_OFFSET:EXFAT_VOLSIZE_OFFSET+8])[0]  
  vbr[ 'volSize' ] = volSize
  fat1Addr = unpack('<L', vbrData[EXFAT_FAT1_OFFSET:EXFAT_FAT1_OFFSET+4])[0]
  vbr[ 'fat1Addr' ] = fat1Addr
  fatSize = unpack('<L', vbrData[EXFAT_FATSIZE_OFFSET:EXFAT_FATSIZE_OFFSET+4])[0]
  vbr[ 'fatSize' ] = fatSize
  dataRegionOffset = unpack('<L', vbrData[EXFAT_DATA_OFFSET:EXFAT_DATA_OFFSET+4])[0]
  vbr[ 'dataRegionOffset' ] = dataRegionOffset
  nbClusters = unpack('<L', vbrData[EXFAT_NB_CLUSTERS:EXFAT_NB_CLUSTERS+4])[0]
  vbr[ 'nbClusters' ] = nbClusters
  rootDirCluster = unpack('<L', vbrData[EXFAT_ROOT_CLUSTER_OFFSET:EXFAT_ROOT_CLUSTER_OFFSET+4])[0]
  vbr[ 'rootDirCluster' ] = rootDirCluster
  sn = vbrData[EXFAT_SN_OFFSET:EXFAT_SN_OFFSET+4]
  version = unpack('<H', vbrData[EXFAT_VERSION_OFFSET:EXFAT_VERSION_OFFSET+2])[0]
  sectorSize = 1 << ord(vbrData[EXFAT_SECTOR_SIZE_OFFSET])
  vbr[ 'sectorSize' ] = sectorSize
  sectorsPerCluster = 1 << ord(vbrData[EXFAT_CLUSTER_SIZE_OFFSET])
  vbr[ 'sectorsPerCluster' ] = sectorsPerCluster
  return vbr

FIRST_CLUSTER_NUMBER=2  

#read and return a cluster
#there is no cluster#0 and cluster#1, first cluster is cluster#2  
def readClusters( f, vbr, cluster, nbCluster=1 ):
  offset = vbr['dataAreaStart']+ (cluster-FIRST_CLUSTER_NUMBER)*vbr['sectorSize']*vbr['sectorsPerCluster']
  #print 'offset cluster=0x%x' % offset
  f.seek(offset)
  if nbCluster>vbr[ 'nbClusters' ]:
    print 'error: length out of range %d' % nbCluster
    return None
  return f.read( vbr['sectorSize']*vbr['sectorsPerCluster']*nbCluster ) 

# return a string representing date and time from a 32 bits long (DOS format)  
# 32bits layout: yyyyyyym mmmddddd hhhhhmmm mmmsssss  
def getDateTimeStr( datetime, ms ):
  if datetime==None or ms==None:
    return ' '*23
  year = (datetime>>25)+1980
  month = (datetime>>21)&0xf
  day = (datetime>>16)&0x1f
  hour = (datetime>>11)&0x1f
  min = (datetime>>5)&0x3f
  sec = (datetime&0x1f)<<1 #(15 means 30secs)
  return "%4d/%02d/%02d %02d:%02d:%02d:%03d" % (int(year), int(month), int(day), int(hour), int(min), int(sec), int(ms) )

ENTRY_ATTR_ATTR_MASK=0x20  
ENTRY_ATTR_DIR_MASK=0x10  
ENTRY_ATTR_SYSTEM_MASK=0x04
ENTRY_ATTR_HIDDEN_MASK=0x02  
ENTRY_ATTR_RO_MASK=0x01

#returns a string representing file attributes  
def getFileAttributesStr( attr ):
  if attr==None:
    return ' '*5
  arc = dir = syst = hid = ro = '-'
  if attr&ENTRY_ATTR_ATTR_MASK:
    arc='a'  
  if attr&ENTRY_ATTR_DIR_MASK:
    dir='d'  
  if attr&ENTRY_ATTR_SYSTEM_MASK:
    syst='s' 
  if attr&ENTRY_ATTR_HIDDEN_MASK:
    hid='h' 
  if attr&ENTRY_ATTR_RO_MASK:
    ro='r'     
  return '%c%c%c%c%c' % (arc, dir, syst, hid, ro)  

def isDir( entry ):
  return entry['entryAttr']&ENTRY_ATTR_DIR_MASK > 0
  
# return next cluster number from FAT
# input: real cluster number (not ajusted)  
def nextCluster( f, vbr, cluster ):
  offsetFat = vbr[ 'fat1Start' ]
  if (cluster*4) > ( vbr['fatSize']*vbr['sectorSize'] ) or cluster<2:
    print 'error: cluster %d out of FAT' % cluster
    return None
  f.seek( offsetFat+(cluster*4) )
  v = f.read(4)
  return unpack('<L', v[0:4])[0]

#returns content while chaining with FAT   
def readClustersFat( f, vbr, cluster ):
  clusterData = '' #read all clusters by following the chaining in FAT
  while cluster!=0xffffffff:
    clusterData = clusterData + readClusters( f, vbr, cluster, 1 ) #cluster number is ajusted (-2) in readCluster()
    cluster = nextCluster( f, vbr, cluster )
  return clusterData

#no chaining, clusters are contiguous    
def readClustersNoFat( f, vbr, cluster, sizeInClusters ):    
  return readClusters( f, vbr, cluster, sizeInClusters )

#compute how many clusters are needed to store a given content size
def size2Clusters( vbr, size ):
  #compute size in clusters
  sizeInClusters = size / (vbr['sectorsPerCluster']*vbr['sectorSize'])
  if size % (vbr[ 'sectorsPerCluster' ]*vbr['sectorSize']) >0: #remainder of the division
    sizeInClusters = sizeInClusters+1
  return sizeInClusters  

#read and return content, whatever clusters are chained in FAT or contiguous   
def readContent( f, vbr, entry ):  
  if entry['noFatChain']:
    sizeInClusters = size2Clusters( vbr, entry['dataLen'] )
    data = readClustersNoFat( f, vbr, entry['entryCluster'], sizeInClusters ) #read contiguous clusters
  else:  
    data = readClustersFat( f, vbr, entry['entryCluster'] ) #read chained cluster using FAT
  return data[:entry['dataLen']]  #truncate last cluster with real content size

#better memory management: use only one cluster as buffer, instead of whole content size like in readContent()  
#'fout' must be opened before in "wb" mode, and will be closed outside this function
def extractContent( f, vbr, entry, fout ):
  sizeInClusters = entry['dataLen'] / (vbr['sectorSize']*vbr['sectorsPerCluster'])  #rounded to clusterSize
  remainder = entry['dataLen'] % (vbr['sectorSize']*vbr['sectorsPerCluster'])     
  if entry['noFatChain']: #contiguous clusters
    if remainder>0:
      clusterList = range( entry['entryCluster'], entry['entryCluster']+sizeInClusters+1 )
    else:  
      clusterList = range( entry['entryCluster'], entry['entryCluster']+sizeInClusters )
  else:
    clusterList = getChainedClustersList( f, vbr, entry['entryCluster'] ) 
  for cluster in clusterList[:-1]: #all clusters but latest
    data = readClusters( f, vbr, cluster, 1 )
    fout.write(data)
  data = readClusters( f, vbr, clusterList[-1], 1 )  #latest 
  if remainder>0:
    fileTail = remainder
  else:
    fileTail = vbr['sectorSize']*vbr['sectorsPerCluster'] #latest cluster is fully used  
  fout.write(data[:fileTail])    
  
#get list of chained cluster for a starting cluster  
def getChainedClustersList( f, vbr, cluster ):
  clusterList = []
  while cluster!=0xffffffff:
    clusterList.append( cluster )
    cluster = nextCluster( f, vbr, cluster )
  return clusterList  
  
def countChainedClusters( f, vbr, cluster ):
  clusterList = getChainedClustersList( f, vbr, cluster )
  return len(clusterList)

#return size in clusters, whatever content is contiguous or not  
def countClusters( f, vbr, entry ):
  if entry['noFatChain']:
    return size2Clusters( vbr, entry['dataLen'] )
  else:    
    return countChainedClusters( f, vbr, entry['entryCluster'] )
    
def fsstat( partition, vbr ):
  print 'FILE SYSTEM INFORMATION'
  print '--------------------------------------------'
  print 'File System Type: %s' % vbr[ 'signature' ]
  print 'Sector size: %d bytes' % vbr['sectorSize'] 
  print 'Cluster size: %d sectors' % vbr['sectorsPerCluster']
  print 'FAT size: %d sectors' % vbr['fatSize']
  print 'Data area size: %d clusters' % vbr['nbClusters']
  print 'Volume label: %s' % vbr[ 'volumeLabel' ]
  vbr2Sector = vbr[ 'vbr1Start' ]+ 12*SECTOR_SIZE #each VBR is 12 sectors long
  print 'VBR#1 0x%08x-0x%08x (sectors %d-%d)' % ( vbr[ 'vbr1Start' ], vbr2Sector, 
    vbr[ 'vbr1Start' ]/SECTOR_SIZE, vbr[ 'vbr1Start' ]/SECTOR_SIZE +12 )
  print 'VBR#2 0x%08x-0x%08x (sectors %d-%d)' % ( vbr2Sector, vbr2Sector+12*SECTOR_SIZE, 
    vbr2Sector/SECTOR_SIZE, vbr2Sector/SECTOR_SIZE +12 )
    
  print 'FAT#1 0x%08x-0x%08x (sectors %d-%d)' % ( vbr[ 'fat1Start' ], vbr[ 'fat1Start' ]+ vbr['fatSize']*SECTOR_SIZE,
    vbr[ 'fat1Start' ]/SECTOR_SIZE, vbr[ 'fat1Start' ]/SECTOR_SIZE + vbr['fatSize'])
  endOfdataArea = vbr[ 'dataAreaStart' ] + vbr['sectorsPerCluster']*vbr['sectorSize']*vbr['nbClusters']
  print 'dataArea 0x%08x-0x%08x (sectors %d-%d, clusters %d-%d)' % ( vbr[ 'dataAreaStart' ], endOfdataArea,
    vbr[ 'dataAreaStart' ]/SECTOR_SIZE, endOfdataArea/SECTOR_SIZE, FIRST_CLUSTER_NUMBER, vbr['nbClusters']+FIRST_CLUSTER_NUMBER )

  rootDir = vbr['dataAreaStart'] + vbr['sectorSize']*vbr['sectorsPerCluster']*(vbr['rootDirCluster']-FIRST_CLUSTER_NUMBER)
  print 'rootDir at 0x%x (sector %d, cluster %d)' % ( rootDir, rootDir/SECTOR_SIZE, vbr['rootDirCluster'] )
  print

#did not find suited unicode or encode() function, should be encode('ascii','ignore'), no ?  
def unicode2ascii( name ):
  if name.__class__ is not unicode:
    return name
  else:
    str = ''
    for i in range(0, len(name), 2):
      str = str + name[i]
    return str 

# directory entries constants  
EXFAT_DIRRECORD_SIZE=32  

EXFAT_DIRRECORD_BITMAP=0x81
EXFAT_DIRRECORD_UPCASE=0x82
EXFAT_DIRRECORD_LABEL=0x83
EXFAT_DIRRECORD_NOLABEL=0x03    
EXFAT_DIRRECORD_FILEDIR=0x85
EXFAT_DIRRECORD_DEL_FILEDIR=0x05
EXFAT_DIRRECORD_VOLUME_GUID=0xA0
EXFAT_DIRRECORD_STREAM_EXT=0xC0
EXFAT_DIRRECORD_DEL_STREAM_EXT=0x40
EXFAT_DIRRECORD_FILENAME_EXT=0xC1
EXFAT_DIRRECORD_DEL_FILENAME_EXT=0x41
    
NOT_FAT_CHAIN_FLAG=0x02    
    
#returns a string describing a directory entry
def getDirEntryLong( entry, path ):
  fullPath = path + unicode2ascii( entry['name'] )
  if entry['noFatChain']:
    nfc = 'nfc'
  else:
    nfc = 'fat'  
  # entry['name'].encode('ascii','ignore')  
  typeStr = ''
  deleted = ''
  if debugLevel>0:
    typeStr = '0x{:02x}: '.format(entry['type'])
    if EXFAT_DIRRECORD_DEL_FILEDIR==entry['type']:
      deleted = ' (deleted)'
  return '%s i=%7d l=%7d %s m=%s a=%s b=%s sc=%d %s %s%s' % ( typeStr, entry['entryCluster'], 
    entry['dataLen'], getFileAttributesStr ( entry['entryAttr'] ),
    getDateTimeStr( entry['modified'], entry['modified10ms'] ), getDateTimeStr( entry['accessed'], 0 ),
    getDateTimeStr( entry['created'], entry['created10ms'] ), entry['secondaryCount'], nfc, fullPath, deleted )

def getDirEntry( entry, path, long=False ):
  fullPath = path + unicode2ascii( entry['name'] )
  if long:
    return getDirEntryLong( entry, path )
  else:   
    return '%s %s %7d %7d %s' % ( getDateTimeStr( entry['modified'], entry['modified10ms'] ),
      getFileAttributesStr ( entry['entryAttr'] ), entry['entryCluster'], entry['dataLen'], 
      fullPath )

def printDirRecord85( record ): #and 0x05
  type = ord( record[0] )
  print '%02x:file dir entry, sc=%d' % ( type, ord( record[1] ) ), #sc = secondary count
  print getDateTimeStr( unpack('<L', record[8:12])[0], ord(record[20]) ),
  if type==EXFAT_DIRRECORD_DEL_FILEDIR:
    print ' (deleted)'
  else: #0x85
    print      
    
def printDirRecordC0( record ): #and 0x40
  type = ord( record[0] )
  print '%02x:stream ext' % type,
  #cluster, datalen, valid datalen, name len
  print 'i=%d l=%d vl=%d nl=%d' % ( unpack('<L', record[20:24])[0], 
    unpack('<Q', record[24:32])[0], unpack('<Q', record[8:16])[0], ord(record[3]) ),
  if ord(record[1])&NOT_FAT_CHAIN_FLAG > 0:
    print 'nfc',
  else:
    print 'fat',
  if type==EXFAT_DIRRECORD_DEL_STREAM_EXT:
    print ' (deleted)'
  else: #0xC0
    print
    
def printDirRecordC1( record ): #and 0x41
  type = ord( record[0] )    
  print '%02x:filename ext=' % type,
  print unicode( record[2: EXFAT_DIRRECORD_SIZE] ),
  if type==EXFAT_DIRRECORD_DEL_FILENAME_EXT:
    print ' (deleted)'
  else: #0xC1
    print
              
ENTRY_STATE_START=0    
ENTRY_STATE_85_SEEN=1
ENTRY_STATE_LAST_C1_SEEN=2

#retrieve even deleted entries 0x05, 0x41, 0x40 and special entries 0x81, 0x82, 0x83, 0x03
#getEntry do not display them if debugLevel==0    
def parseDir( f, vbr, clusterData ):
  offset = 0
  entryState = ENTRY_STATE_START
  dir = [] #start of directory, no entries yet
  remainingSC = 0
  while offset<len(clusterData) and ord(clusterData[offset])!=0:
    type = ord(clusterData[offset])
    if type==EXFAT_DIRRECORD_LABEL:
      count = ord( clusterData[offset+1] )
      label = unicode( clusterData[offset+2:offset+count*2], errors='ignore')
      if debugLevel>1:
        print '83:label= ' + label
      vbr[ 'volumeLabel' ] = unicode2ascii(label) 
    elif type==EXFAT_DIRRECORD_NOLABEL:
      if debugLevel>1:
        print '03:no label'
      vbr[ 'volumeLabel' ] = ''
    elif type==EXFAT_DIRRECORD_BITMAP or type==EXFAT_DIRRECORD_UPCASE:
      #create 'virtual' entry
      entryCluster = unpack('<L', clusterData[offset+20:offset+24])[0]    
      dataLen = unpack('<Q', clusterData[offset+24:offset+32])[0]
      vEntry = dict()
      vEntry['type'] = type
      vEntry['dataLen'] = dataLen
      vEntry['entryCluster'] = entryCluster
      #no real dates and times
      vEntry['modified']=vEntry['created']=vEntry['accessed']=vEntry['modified10ms']=vEntry['created10ms']=None
      vEntry['entryAttr'] = 0
      vEntry['secondaryCount']=0
      vEntry['noFatChain'] = True
      if type==EXFAT_DIRRECORD_BITMAP:
        vbr[ 'bitmapCluster' ] = entryCluster
        vbr[ 'bitmapLength' ] = dataLen   
        vEntry['name'] = 'bitmap'
        vbr[ 'bitmapEntry' ] = vEntry  
        if debugLevel>1:
          print '81:bitmap', 
      else: #0x82 EXFAT_DIRRECORD_UPCASE
        vbr[ 'upcaseCluster' ] =  entryCluster
        vbr[ 'upcaseLength' ] = dataLen   
        vEntry['name'] = 'upcase'
        if debugLevel>1:
          print '82:upcase entry',
      dir.append( vEntry )      
      if debugLevel>1:
        print '%x %d' % ( entryCluster, dataLen)
    elif type==EXFAT_DIRRECORD_VOLUME_GUID:
      if debugLevel>1:
        print 'a0:volume GUID entry'  
    elif (type&0x7f)==EXFAT_DIRRECORD_DEL_FILEDIR: #or 0x85
      if debugLevel>1:
        printDirRecord85( clusterData[offset:offset+EXFAT_DIRRECORD_SIZE] )
      #0x85 is always followed by C0 and C1, remaining 32 bytes entries for this dir entry is given by secondaryCount
      entry = dict()
      entry['type'] = type
      entry['seenRecords'] = [ type ]
      entry['secondaryCount'] = ord( clusterData[offset+1] ) 
      remainingSC = entry['secondaryCount']
      entryAttr = unpack('<H', clusterData[offset+4:offset+6])[0]
      entry['entryAttr']=entryAttr
      created = unpack('<L', clusterData[offset+8:offset+12])[0]
      modified = unpack('<L', clusterData[offset+12:offset+16])[0]
      accessed = unpack('<L', clusterData[offset+16:offset+20])[0]
      created10ms = ord(clusterData[offset+20])
      modified10ms = ord(clusterData[offset+21])
      entry['created']=created
      entry['modified']=modified
      entry['accessed']=accessed
      entry['created10ms']=created10ms
      entry['modified10ms']=modified10ms
      if type==EXFAT_DIRRECORD_FILEDIR:
        entryState = ENTRY_STATE_85_SEEN
        
    elif (type&0x7f)==EXFAT_DIRRECORD_DEL_STREAM_EXT: #or 0xC0
      if debugLevel>1: #only display debug
        printDirRecordC0( clusterData[offset:offset+EXFAT_DIRRECORD_SIZE] )  
      if entryState == ENTRY_STATE_85_SEEN:
        remainingSC = remainingSC-1
        nameLen = ord(clusterData[offset+3])
        entry['nameLen'] = nameLen
        entry['readNameLen']=0
        entryCluster = unpack('<L', clusterData[offset+20:offset+24])[0]    
        entry['entryCluster'] = entryCluster
        dataLen = unpack('<Q', clusterData[offset+24:offset+32])[0]
        entry['dataLen'] = dataLen
        validDataLen = unpack('<Q', clusterData[offset+8:offset+16])[0]
        entry['validDataLen'] = validDataLen
        entry['name']=''
        if ord(clusterData[offset+1])&NOT_FAT_CHAIN_FLAG > 0: #no FAT chain
          entry['noFatChain'] = True
        else:
          entry['noFatChain'] = False
        
    elif (type&0x7f)==EXFAT_DIRRECORD_DEL_FILENAME_EXT: #or 0xc1
      filename = unicode( clusterData[offset+2: offset+EXFAT_DIRRECORD_SIZE], errors='ignore')
      if debugLevel>1: #only display debug
        printDirRecordC1( clusterData[offset:offset+EXFAT_DIRRECORD_SIZE] )
      if entryState == ENTRY_STATE_85_SEEN:        
        if remainingSC >= 1: #concatenate only if remainingSC>0, IE if 0x85 and 0xC0 have been seen before
          entry['name'] = entry['name']+filename
          remainingSC = remainingSC-1
          if remainingSC==0: #last 0xC1
            entry['name'] = entry['name'][:entry['nameLen']*2] #truncate to real length
            if debugLevel>1:
              print '  ', unicode2ascii( entry['name'] )
            dir.append( entry )  
            entryState = ENTRY_STATE_LAST_C1_SEEN
    else:
      if debugLevel>1:
        print '0x%02x:unknown' % type
    offset = offset + EXFAT_DIRRECORD_SIZE
  return dir  

#returns list of root dir entries  
def readRootDir( f, vbr, firstCluster ):
  clusterData = readClustersFat( f, vbr, firstCluster )  #content length is not known (exception is rootdir)
  return parseDir( f, vbr, clusterData )

def readDir( f, vbr, entry ):  
  content =  readContent( f, vbr, entry )
  return parseDir( f,vbr, content )

#recursice fls  
def fls( f, vbr, dir, path, recur, long=False ):
  for entry in dir:
    entryStr = None
    if debugLevel>0 or ( entry['type']==EXFAT_DIRRECORD_FILEDIR ):
      entryStr = getDirEntry( entry, path, long ) #get string describing this entry
    if entryStr != None:
      print entryStr
      if isDir( entry ) and recur:
        #path = path + unicode2ascii( entry['name'] ) + '/'
        subdir = readDir( f, vbr, entry )
        fls( f, vbr, subdir, path + unicode2ascii( entry['name'] ) + '/', recur, long )

#called first time with rootdir content        
def getFiles( f, vbr, dir, globalList ):
  for entry in dir:
    #print entry
    if entry['type']==EXFAT_DIRRECORD_FILEDIR:    
      globalList.append( entry ) #add each entry individually, as tree leaves
      #print getDirEntry( entry )
      if isDir( entry ):
        subdir = readDir( f, vbr, entry ) #dir clusters
        getFiles( f, vbr, subdir, globalList )

#like chkdsk DOS command (seems 512 bytes are added to files)        
def contentStat( f, vbr, globalList ):
  files = dir = 0
  filesContentSize = dirContentSize = 0

  for entry in globalList:
    if isDir(entry):
      dir = dir + 1
      dirContentSize = dirContentSize + entry['dataLen']
    else:
      files = files + 1  
      filesContentSize = filesContentSize + entry['dataLen']
  print 'Directories: %d (%d Kb)' % (dir, dirContentSize/1024),
  print 'Files: %d (%d Kb)' % (files, filesContentSize/1024)
  
  bitmap = readContent( f, vbr, vbr[ 'bitmapEntry' ] )
  allocClusters = countBitmap( bitmap )
  freeClusters = vbr['nbClusters']-allocClusters
  
  #roots dir has clained clusters
  rootDirClusterSize = countChainedClusters( f, vbr, vbr['rootDirCluster'] )
  
  print 'Rootdir: %d clusters (%d Kb)' % ( rootDirClusterSize, 
    (rootDirClusterSize*vbr['sectorsPerCluster']*vbr['sectorSize'])/1024 )
  print 'Bitmap= %d available clusters (%d Kb), %d free clusters (%d Kb), %d allocated clusters (%d Kb)' % ( 
    vbr['nbClusters'], (vbr['nbClusters']*vbr['sectorsPerCluster']*vbr['sectorSize'])/1024,
    freeClusters, (freeClusters*vbr['sectorsPerCluster']*vbr['sectorSize'])/1024, 
    allocClusters, (allocClusters*vbr['sectorsPerCluster']*vbr['sectorSize'])/1024 )
  print
        
def usage():
  print 'usage: exfat_dump.py command [options] imagefile [entry_number]'
  print 'commands:'
  print ' mmls = print partitions information'
  print ' fls = lists directory entries. Options are -o -r -l'
  print ' fsstat : filesystem information. Options: -o'
  print ' icat : dumps file content (entry_number required)'
  print ' istat : directory or file meta information (entry_number required)'
  print ' Options:'
  print ' -o = partition offset. Optional, by default use first partition with type=7'
  print ' -l = long (detailed) information'
  print ' -r = recursively lists directories content'
  print ' -h = compute SHA1 for extracted file'
  print ' -d debug_level (0 -default-, 1 or 2)'
  print 
  sys.exit()  
  
def CountBits(n):
  n = (n & 0x55555555) + ((n & 0xAAAAAAAA) >> 1)
  n = (n & 0x33333333) + ((n & 0xCCCCCCCC) >> 2)
  n = (n & 0x0F0F0F0F) + ((n & 0xF0F0F0F0) >> 4)
  n = (n & 0x00FF00FF) + ((n & 0xFF00FF00) >> 8)
  n = (n & 0x0000FFFF) + ((n & 0xFFFF0000) >> 16)
  return n

def countBitmap( content ):
  if debugLevel>1:
    print 'Bitmap:'
    print hexlify(content)
  l = len(content)/4
  r = len(content)%4
  allocated = 0
  for i in range(l):
     allocated = allocated + CountBits( unpack('<L', content[i*4:(i+1)*4])[0] )
  if r>0: #not fully tested ... yet
    v = unpack('<L', content[-4:])[0]
    if r==3:
      v = v&0xffffff00
    elif r==2:
      v = v&0xffff0000
    else:
      v = v&0xff000000
  allocated = allocated + CountBits( v )       
  return allocated   

#minimal istat command which gives additionnal info compared to fls -l, for directories or files  
def istat( f, vbr, entry ):
  if entry['noFatChain']:
    print 'clusterList: [%d:%d]' % ( cluster, cluster + size2Clusters( vbr, entry['dataLen'] )-1 )
  else:
    clusterList = getChainedClustersList( f, vbr, cluster )
    print 'clusterList:', clusterList  

print 'exFAT_dump v0.2 (lclevy@free.fr, https://github.com/lclevy/)'
print
    
if len(sys.argv)<3:
  usage()

#parameter handling  
command = sys.argv[1]  
cluster = -1

#verify if command is ok
if command not in [ 'istat', 'icat', 'fsstat', 'fls', 'mmls' ]:
  print 'unsupported command: %s' % command
  usage()  

#i commands requires an additional entry argument after imagefile 
if command!='icat' and command!='istat':   
  f=open(sys.argv[-1], 'rb') #last argument is filename
else:
  if len(sys.argv)>=4: #icat or istat
    f=open(sys.argv[-2], 'rb')
    cluster = int(sys.argv[-1]) # last argument is entry number
  else:
    usage()
    
pl = readMBR( f )   
if command=='mmls':
  displayMBR( pl )
  f.close()
  sys.exit()
 
if pl==None: #no partition on this disk!
  print 'no partition'
  sys.exit()

#possible improvement: use https://docs.python.org/2/library/argparse.html#module-argparse
  
params = dict()
i = 2 #start at argument #2
recursive = False
fullPath = False
bodyOutput = False
debugLevel = 0
partOffset = 0
hashFile = False
longList = False
while i < (len(sys.argv)-1): #parses arguments starting with -
  #print sys.argv[i]
  if sys.argv[i][0]=='-': #option
    if sys.argv[i]=='-o' and len(sys.argv)>i: #with start offset
      partOffset = int(sys.argv[i+1])
      i = i+1
    elif sys.argv[i]=='-d' and len(sys.argv)>i: #with debug level
      debugLevel = int(sys.argv[i+1])
      i = i+1
    elif sys.argv[i]=='-r':    
      recursive = True
    elif sys.argv[i]=='-p':    
      fullPath = True
    elif sys.argv[i]=='-m':    
      bodyOutput = True
    elif sys.argv[i]=='-h':    
      hashFile = True
    elif sys.argv[i]=='-l':    
      longList = True      
    else:
      print 'error: invalid argument %s' % sys.argv[i]
      f.close()
      sys.exit()      
  i = i+1 #next argv   
  
if debugLevel>0:
  print 'command=',command, '-o', partOffset, 'cluster', cluster, '-r', recursive, '-p', fullPath, '-d', debugLevel, '-l', longList, '-h', hashFile

f.seek(0, 2) #end of file  
dumpSectorSize = f.tell() / SECTOR_SIZE  
        
foundPartition = False  
partition = None
      
if partOffset==0 and len(pl)>0:
  for p in pl: #if -o not used, will use the first non empty partition with type==7
    boot, type, start, size = p
    if ord(type)==PARTITION_TYPE_NTFS_EXFAT and size>0 and start>0: #must be of type==7, size>0 and starting sector>0
      partOffset = start
      foundPartition = True  
      partition = p
      break
else: 
  for p in pl: #verify given -o offset is a valid string offset
    if p[2]==partOffset:
      foundPartition = True
      partition = p
      break
 
if foundPartition==False:
  print 'error: -o value is not a valid start of partition'
  f.close()
  sys.exit()  
  
if partOffset > dumpSectorSize:
  print 'error: -o sector out of range'
  f.close()
  sys.exit()  
  
if command=='mmls' or debugLevel>0:
  displayMBR( pl )
vbr = readVBR( f, partOffset ) 

#compute and save bytes offsets with values from VBR
vbr1Start = vbr[ 'vbr1Offset' ]*vbr['sectorSize']
vbr[ 'vbr1Start' ] = vbr1Start
fat1Start = vbr[ 'fat1Addr' ]*vbr['sectorSize'] + vbr[ 'vbr1Start' ]
vbr[ 'fat1Start' ] = fat1Start
dataAreaStart = vbr1Start+vbr['dataRegionOffset']*vbr['sectorSize']
vbr[ 'dataAreaStart' ] = dataAreaStart

#get rootdir early to get VolumeLabel, bitmap and upcase information
rootDir = readRootDir( f, vbr, vbr['rootDirCluster'] )

#get all files and directories
globalList = []
getFiles( f, vbr, rootDir, globalList )
  
if command=='fsstat' or debugLevel>0:
  fsstat( partition, vbr )
  contentStat( f, vbr, globalList )
  
if command=='fls':
  fls( f, vbr, rootDir, '/', recursive, longList )
elif debugLevel>0:
  fls( f, vbr, rootDir, '/', False, True )
    
if command=='icat' or command=='istat':
  #check cluster number is inside cluster Area
  if (cluster<FIRST_CLUSTER_NUMBER or cluster>vbr[ 'nbClusters' ]):
    print 'error: cluster out of range'
    f.close()
    sys.exit()
  if cluster==vbr['rootDirCluster']: 
    if command=='istat':
      clusterList = getChainedClustersList( f, vbr, cluster )
      print 'clusterList:', clusterList
    else:
      print 'icat invalid on directory entry'    
  else:  #not rootDir
    entrySize = -1  
    for entry in globalList: #check if entry is in existing file/dir entries
      if entry['entryCluster']==cluster:
        entrySize = entry['dataLen']
        break
    if entrySize<0: #cluster number not found
      print 'incorrect cluster number'
      f.close()
      sys.exit()
    if command=='icat': #extract file content
      if isDir( entry ):
        print 'icat invalid on directory entry'  
      else:  
        if entrySize>0:
          fout = open( unicode2ascii(entry['name']), 'wb')
          extractContent( f, vbr, entry, fout )
          fout.close()  
          if hashFile:
            fin = open( unicode2ascii(entry['name']), 'rb')
            content = fin.read()
            print sha1(content).hexdigest()
            fin.close()
        elif entrySize==0:
          print 'emptyFile'
    else: 
      istat( f, vbr, entry )
  
f.close()
