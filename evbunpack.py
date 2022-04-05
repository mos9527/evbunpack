from argparse import ArgumentParser
from mmap import mmap,ACCESS_READ
import struct,sys,io,os,math
from const import *
from aplib import decompress
blocksize = 8 * 1024 ** 2 # 8MB

def unpack(structure, buffer, *args):
    '''Unpack buffer by structure given'''    
    fmt, desc = zip(*filter(lambda p:isinstance(p, tuple),structure))    
    fmt = f'<{"".join(fmt)}' % args
    unpacked = struct.unpack_from(fmt, buffer, 0)
    return {k: v for k, v in zip(desc, unpacked) if k}

def read_metadata(source : io.BufferedIOBase): 
    '''Reads current container\'s "meta" elements,seek to where the raw data begins

       Returns `(EVB_PACK_HEADER -> header,EVB_NODE_MAIN -> main_node)`
    '''
    def seek_to_magic(magic=b'EVB\x00'):
        result = mmap(source.fileno(),0,access=ACCESS_READ).find(magic)
        if result >= 0:
            print('[-] Found magic at',hex(result))
            source.seek(result,0)
            return True                
    assert seek_to_magic(),'Magic not found'
    header = unpack(EVB_PACK_HEADER, source.read(64))
    main_node = unpack(EVB_NODE_MAIN, source.read(16))        
    source.read(11) # pad(11)
    main_node['data'] = source.read(main_node['size'] - 16 - 11) # appends main node data (contained pad)
    source.read(4) # pad(4)
    return header,main_node

def generate_nodes(main_node):
    '''Iterate and generate node objects from `main_node` produced by `read_metadata`'''
    data = io.BytesIO(main_node['data'])
    while True:
        def unpack_named():
            blkObjCount = data.read(4)  # would always be 0        
            blkFilename = bytearray()                            
            p = data.read(2)
            while p[0]!=0x00:                                
                blkFilename.extend(p)
                p = data.read(2)       
            data.seek(-2,1)     
            block = blkObjCount + blkFilename + data.read(EVB_NODE_NAMED[-1])
            # For EVB_ (const member), last element correspond to the size of a complete block
            return unpack(EVB_NODE_NAMED, block, len(blkFilename))

        def unpack_optional(named_node):                
            if named_node['type'] == NODE_TYPE_FOLDER:            
                blk = data.read(EVB_NODE_OPTIONAL_FOLDER[-1])
                return unpack(EVB_NODE_OPTIONAL_FOLDER, blk)
            elif named_node['type'] == NODE_TYPE_FILE:
                blk = data.read(EVB_NODE_OPTIONAL_FILE[-1])
                if data.tell() + 12 < len(main_node['data']): # skip 12 pad bytes for files
                    data.read(12)            
                return unpack(EVB_NODE_OPTIONAL_FILE, blk)                

        def decodeNode(**node):
            node['name'] = node['name'].decode('utf-16')        
            return node

        named_node = unpack_named()
        optional_node = unpack_optional(named_node)
        complete_node = decodeNode(**named_node,**optional_node)
        if complete_node: yield complete_node

if __name__ == "__main__":
    parser = ArgumentParser(description='Enigma Vitural Box external package / executable unpacker')
    parser.add_argument('file', help='EVB external package (container) / packed PE path')
    parser.add_argument('output', help='Output directory')
    args = parser.parse_args()
    file, output = args.file, args.output
    print('[-] Opening',file)
    source = open(file, 'rb')    
    try:
        header,main_node = read_metadata(source)
        print('[-] Metadata parsed')
    except AssertionError as e:
        print('ERROR : File magic mismatch:',e)        
        sys.exit(1)            
    nodes = generate_nodes(main_node)
    
    def traverse(node,path_prefix=output,level=0):
        path = os.path.join(path_prefix,node['name'])
        print(end='...' * level)
        if node['type'] == NODE_TYPE_FILE:
            with open(path,'wb') as output:
                rsize = node['original_size']
                ssize = node['stored_size']
                if rsize != ssize:
                    print('Decompressing (%d bytes -> %d bytes)' % (ssize,rsize),path)
                    source.read(12) # for compressed content only
                    decompressed = decompress(source.read(ssize),strict=True)                    
                    output.write(decompressed)
                else:
                    print('Extracting (%d bytes)' % ssize,path)
                    output.write(source.read(ssize))
        elif node['type'] == NODE_TYPE_FOLDER:            
            if not os.path.isdir(path):os.makedirs(path)
            print('Created folder',path)
            for i in range(0,node['objects_count']):
                traverse(next(nodes),path_prefix=path,level=level + 1)    
    
    traverse(next(nodes))