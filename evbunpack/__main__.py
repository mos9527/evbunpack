#-*- coding: utf-8 -*-
# Copy
import struct,os,array,time,math,sys
from argparse import ArgumentParser
from mmap import mmap,ACCESS_READ
from evbunpack.aplib import decompress
from evbunpack.const import *

_tick,_val,_max = 0,0,0
def report_extraction_progress(message,now,total):
    phases = (' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█')        
    _base  = lambda x:int(math.log2(x) // 10 if x > 0 else 0)
    _hrs   = lambda x:'%.2f' % (x/2**(10*_base(x))) + ('B', 'kB', 'MB', 'GB', 'TB')[_base(x)]
    global _tick,_val,_max    
    if _max != total:
        _max = total
        _val = now
        _tick = time.time()
    dt = time.time() - _tick
    dy = now - _val
    _tick = time.time()
    _val = now
    r = dy / dt if dt > 0 else dy
    print(phases[len(phases) * now//total],message,_hrs(now),'/',_hrs(total),_hrs(r)+'/s',' ' * 20,end='\r')

def write_bytes(fd,out_fd,size,chunk_sizes=None,chunk_process=None,default_chunksize=65536):
    bytes_read   = 0
    bytes_wrote = 0
    inital_offset = fd.tell()
    while bytes_read < size:
        report_extraction_progress('Extracting...',bytes_read,size)
        
        chunk_size = next(chunk_sizes) if chunk_sizes else default_chunksize        
        size_to_read = min(chunk_size,size - (fd.tell() - inital_offset))

        chunk = fd.read(size_to_read)
        bytes_read += len(chunk)

        chunk = chunk if not chunk_process else chunk_process(chunk)        
        
        bytes_wrote += out_fd.write(chunk)
    return bytes_wrote

def unpack(structure, buffer, *args, **extra):
    '''Unpack buffer by structure given'''    
    fmt, desc = zip(*filter(lambda p:isinstance(p, tuple),structure))    
    fmt = f'<{"".join(fmt)}' % args
    unpacked = struct.unpack_from(fmt, buffer, 0)
    return {**{k: v for k, v in zip(desc, unpacked) if k},**extra}

def seek_to_magic(src,magic=b'EVB\x00'):    
    result = mmap(src.fileno(),0,access=ACCESS_READ).find(magic)
    if result >= 0:
        print('[-] Found magic (1st occurence) at',hex(result))
        src.seek(result,0)
        return result
    return False

def read_named_node(src):    
    blkFilename = bytearray()                            
    p = src.read(2)
    while p[0]!=0x00:                                
        blkFilename.extend(p)
        p = src.read(2)       
    src.seek(-2,1)     
    block = blkFilename + src.read(EVB_NODE_NAMED[-1])
    # For EVB_ (const member), last element correspond to the size of a complete block
    return unpack(EVB_NODE_NAMED, block, len(blkFilename),offset=src.tell())    

def read_header_node(src):
    blk = src.read(EVB_HEADER_NODE[-1])
    return unpack(EVB_HEADER_NODE,blk)

def read_optional_legacy_pe_file_node(src):
    blk = src.read(EVB_NODE_OPTIONAL_PE_FILE[-1])    
    return unpack(EVB_NODE_OPTIONAL_PE_FILE, blk)

def read_optional_file_node(src):
    blk = src.read(EVB_NODE_OPTIONAL_FILE[-1])    
    return unpack(EVB_NODE_OPTIONAL_FILE, blk)                

def read_chunk_block(src):
    blk = src.read(EVB_CHUNK_BLOCK[-1])    
    return unpack(EVB_CHUNK_BLOCK, blk)                

def read_pack_header(src):
    blk = src.read(EVB_PACK_HEADER[-1])    
    return unpack(EVB_PACK_HEADER, blk)                

def read_main_node(src):
    blk = src.read(EVB_NODE_MAIN[-1])    
    return unpack(EVB_NODE_MAIN, blk)                

def pe_external_tree(fd):
    # Both PE and external packages work with this method
    start = seek_to_magic(fd)
    assert start is not False,'Magic not found'
    read_pack_header(fd)
    main_node = read_main_node(fd)
    abs_offset = start + main_node['size'] + 68 # offset from the head of the stream
    fd.seek(1,1)
    while True:
        try:
            header_node = read_header_node(fd)
            named_node = read_named_node(fd)
        except struct.error:
            return # Potential EOF exception
        if   named_node['type'] == NODE_TYPE_FILE:
            optional_node = read_optional_file_node(fd)                        
            optional_node['offset'] = abs_offset
            abs_offset += optional_node['stored_size']
        elif named_node['type'] == NODE_TYPE_FOLDER:
            optional_node = {}
            fd.seek(25,1)
        else:            
            return # assuming finished
        named_node['name'] = named_node['name'].decode('utf-16-le')        
        yield {**header_node,**named_node,**optional_node}

def legacy_pe_tree(fd):
    # Older executables has their file table and content placed together
    # Courtesy of evb-extractor!
    assert seek_to_magic(fd) is not False,'Magic not found'
    read_pack_header(fd)
    seek_origin = 0 
    while True:    
        seek_origin = fd.tell()
        try:
            header_node = read_header_node(fd)
            named_node = read_named_node(fd)
        except struct.error:
            return # Potential EOF exception  
        if   named_node['type'] == NODE_TYPE_FILE:
            fd.seek(seek_origin + header_node['size'] + 4 - EVB_NODE_OPTIONAL_PE_FILE[-1])
            optional_node = read_optional_legacy_pe_file_node(fd)                  
            optional_node['offset'] = fd.tell()
            fd.seek(optional_node['stored_size'],1)
        elif named_node['type'] == NODE_TYPE_FOLDER:
            optional_node = {}
            fd.seek(seek_origin + header_node['size'] + 4)
        elif named_node['type'] == NODE_TYPE_MAIN:            
            fd.seek(seek_origin + header_node['size'] + 4)
            continue
        else:            
            return # assuming finished
        named_node['name'] = named_node['name'].decode('utf-16-le')        
        yield {**header_node,**named_node,**optional_node}       

def completed(generator):
    # Complete building the tree before we'd read the file
    for item in list(generator):        
        yield item

if __name__ == "__main__":
    parser = ArgumentParser(description='Enigma Vitural Box Unpacker')
    parser.add_argument('--legacy',help='Enable compatibility mode to work with older (6.x) EVB packages',action='store_true',default=False)
    parser.add_argument('file', help='File to be unpacked')
    parser.add_argument('output', help='Extract destination directory')
    args = parser.parse_args()
    
    sys.stdout = sys.stderr
    # Redirect logs to stderr
    file, output ,legacy = args.file, args.output , args.legacy
    if args.legacy:
        print('[!] Running in legacy mode!')
    print('[-] Reading',file)    
    fd = open(file, 'rb')    
    if legacy:
        nodes = completed(legacy_pe_tree(fd))
    else:
        nodes = completed(pe_external_tree(fd))
    compression_flag = False
    def traverse(node,path_prefix=output,level=0):        
        global compression_flag
        path = os.path.join(path_prefix,node['name'])
        print(end='...' * level)
        if node['type'] == NODE_TYPE_FILE:
            print(node['name'],end='')
            with open(path,'wb') as output:                
                rsize = node['original_size']
                ssize = node['stored_size']
                offset = node['offset']
                fd.seek(offset)
                if not compression_flag and rsize != ssize:    
                    compression_flag = True
                    print('...Compression detected. Using 0x%x as initial offset' % offset)
                if compression_flag:                    
                    chunks_blk = read_chunk_block(fd)                                                                             
                    blkChunkData = fd.read(chunks_blk['size'] - EVB_CHUNK_BLOCK[-1])
                    arrChunkData = (val for idx,val in enumerate(array.array('I',blkChunkData)) if idx % 3 == 0)
                    # Chunk data comes in 12-bytes rotation: Chunk size (4bytes), Total size (4bytes), Padding (4bytes)
                    # But with the last Chunk size, it does not come with Total size or Padding...
                    # Thus filtering only every 3rd elements works. Which should always give us Chunk size
                    # Even if the last 8 bytes is missing
                    print('...Decompress [ssize=%d, rsize=%d, offset=0x%x, offsetBlk=0x%x]' % (ssize,rsize,fd.tell(),chunks_blk['size']))                    
                    wsize = write_bytes(fd,output,size=ssize - chunks_blk['size'],chunk_sizes=arrChunkData,chunk_process=decompress)
                    assert wsize == rsize,"Incorrect size"
                else:
                    print('...Write [size=0x%x, offset=0x%x]' % (ssize,offset))
                    write_bytes(fd,output,size=ssize)                       
        elif node['type'] == NODE_TYPE_FOLDER:        
            if not os.path.isdir(path):
                os.makedirs(path)
            print('Created Folder',path)
            for i in range(0,node['objects_count']):
                traverse(next(nodes),path_prefix=path,level=level + 1)
    print('[-] Beginning traversal...')
    try:
        traverse(next(nodes))
    except StopIteration:                
        print('[!] Magic found. But no filetable can be extracted.')
        print('[!] Try enable / disabling --legacy option to see if that works.')      
        sys.exit(1)
    except AssertionError as e:
        print('[!] While extracting package',e)
        sys.exit(1)
    print('[!] Extraction complete',' ' * 20)
    sys.exit(0)
