# by greats3an 2022
import struct,os
from argparse import ArgumentParser
from mmap import mmap,ACCESS_READ
from evbunpack.aplib import decompress
from evbunpack.const import *

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

def read_offset_block(src):
    blk = src.read(EVB_OFFSET_BLOCK[-1])    
    return unpack(EVB_OFFSET_BLOCK, blk)                

def pe_external_tree(fd):
    # Both PE and external packages work with this method
    start = seek_to_magic(fd)
    assert start is not False,'Magic not found'
    unpack(EVB_PACK_HEADER, fd.read(EVB_PACK_HEADER[-1]))
    main_node = unpack(EVB_NODE_MAIN, fd.read(EVB_NODE_MAIN[-1]))  
    abs_offset = start + main_node['size'] + 68 # offset from the head of the stream
    fd.seek(1,1)
    while True:
        header_node = read_header_node(fd)
        named_node = read_named_node(fd)
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
    unpack(EVB_PACK_HEADER, fd.read(EVB_PACK_HEADER[-1]))   
    seek_origin = 0 
    while True:    
        seek_origin = fd.tell()            
        header_node = read_header_node(fd)        
        named_node = read_named_node(fd)        
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
    parser = ArgumentParser(description='Enigma Vitural Box 解包工具')
    parser.add_argument('--legacy',help='启用兼容模式，适用于老版本封包',action='store_true',default=False)
    parser.add_argument('file', help='封包 EXE 或外部封包文件路径')
    parser.add_argument('output', help='保存路径')
    args = parser.parse_args()
    file, output ,legacy = args.file, args.output , args.legacy
    print('[-] Reading',file)    
    fd = open(file, 'rb')    
    if legacy:
        nodes = completed(legacy_pe_tree(fd))
    else:
        nodes = completed(pe_external_tree(fd))
    def traverse(node,path_prefix=output,level=0):        
        path = os.path.join(path_prefix,node['name'])
        print(end='...' * level)
        if node['type'] == NODE_TYPE_FILE:
            print(node['name'],end='')
            with open(path,'wb') as output:                
                rsize = node['original_size']
                ssize = node['stored_size']
                offset = node['offset']
                fd.seek(offset)
                if rsize != ssize:        
                    offset_blk = read_offset_block(fd)                    
                    print('...Decompress [size=0x%x, offset=0x%x, offsetBlk=0x%x]' % (ssize,offset,offset_blk['size']))
                    fd.seek(offset_blk['size'] - EVB_OFFSET_BLOCK[-1],1) # TODO : make compatible with more PEs
                    wfile = decompress(fd.read(ssize),True)
                    assert len(wfile) == rsize,"Decompression failed"
                    output.write(wfile)
                else:
                    print('...Write [size=0x%x, offset=0x%x]' % (ssize,offset))
                    output.write(fd.read(ssize))
        elif node['type'] == NODE_TYPE_FOLDER:        
            if not os.path.isdir(path):
                os.makedirs(path)
            print('Created Folder',path)
            for i in range(0,node['objects_count']):
                traverse(next(nodes),path_prefix=path,level=level + 1)
    print('[-] Beginning traversal...')
    traverse(next(nodes))
    print('[!] Extraction complete')