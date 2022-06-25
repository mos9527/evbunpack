#-*- coding: utf-8 -*-
# Copy
import struct,os,array,time,math,sys
from argparse import ArgumentParser
from mmap import mmap,ACCESS_READ
from evbunpack.aplib import decompress
from evbunpack.const import *
from evbunpack import __version__

ORIGINAL_PE_SUFFIX = '_original.exe'
FOLDER_ALTNAMES = {
    '%DEFAULT FOLDER%' : ''
}

class Progress:
    _phases = (' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█')        
    _base  = lambda x:int(math.log2(x) // 10 if x > 0 else 0)
    _hrs   = lambda x:'%.2f' % (x/2**(10*Progress._base(x))) + ('B', 'kB', 'MB', 'GB', 'TB')[Progress._base(x)]        
    def __init__(self) -> None:
        self._max = 0
        self._val = 0
        self._tick = time.time()

    def report(self,message,now,total):
        if self._max != total:
            self._max = total
            self._val = now
            self._tick = time.time()
        dt = time.time() - self._tick
        dy = now - self._val
        self._tick = time.time()
        self._val = now
        r = dy / dt if dt > 0 else dy
        print('[%s]'%self._phases[len(self._phases) * now//total],message,Progress._hrs(now),'/',Progress._hrs(total),Progress._hrs(r)+'/s',' ' * 50,end='\r')

Progress.instance = Progress()
def report_extraction_progress(message,now,total):
    return Progress.instance.report(message,now,total)

def write_bytes(fd,out_fd,size,chunk_sizes=None,chunk_process=None,default_chunksize=65536,desc='Extracting...'):
    bytes_read  = 0
    bytes_wrote = 0
    inital_offset = fd.tell()
    while bytes_read < size:
        report_extraction_progress(desc,bytes_read,size)
        chunk_size = next(chunk_sizes) if chunk_sizes else default_chunksize        
        size_to_read = min(chunk_size,size - (fd.tell() - inital_offset))
        chunk = fd.read(size_to_read)
        bytes_read += len(chunk)
        chunk = chunk if not chunk_process else chunk_process(chunk)                
        bytes_wrote += out_fd.write(chunk)
    print(' '* 120,end='\r') # clearing the line
    return bytes_wrote

def get_size_by_struct(struct_):
    fmt , desc = make_format_by_struct(struct_)
    return struct.calcsize(fmt)

def read_bytes_by_struct(src,struct_):
    return src.read(get_size_by_struct(struct_))

def make_format_by_struct(struct, *args):
    fmt, desc = zip(*filter(lambda p:isinstance(p, tuple),struct))    
    fmt = ('<' if type(struct[-1]) != str else struct[-1]) + ("".join(fmt)) % args
    return fmt,desc

def pack(structure,*args):
    fmt,desc = make_format_by_struct(structure)
    return struct.pack(fmt,*args)

def unpack(structure, buffer, *args, **extra):
    '''Unpack buffer by structure given'''    
    fmt,desc = make_format_by_struct(structure,*args)
    unpacked = struct.unpack_from(fmt, buffer, 0)
    return {**{k: v for k, v in zip(desc, unpacked) if k},**extra}

def read_named_node(src):    
    blkFilename = bytearray()                            
    p = src.read(2)
    while p[0]!=0x00:                                
        blkFilename.extend(p)
        p = src.read(2)       
    src.seek(-2,1)     
    block = blkFilename + src.read(3)
    return unpack(EVB_NODE_NAMED, block, len(blkFilename),offset=src.tell())    

def read_header_node(src):    
    return unpack(EVB_HEADER_NODE,read_bytes_by_struct(src,EVB_HEADER_NODE))

def read_optional_legacy_pe_file_node(src): 
    return unpack(EVB_NODE_OPTIONAL_PE_FILE, read_bytes_by_struct(src,EVB_NODE_OPTIONAL_PE_FILE))

def read_optional_file_node(src):      
    return unpack(EVB_NODE_OPTIONAL_FILE, read_bytes_by_struct(src,EVB_NODE_OPTIONAL_FILE))

def read_chunk_block(src):
    return unpack(EVB_CHUNK_BLOCK, read_bytes_by_struct(src,EVB_CHUNK_BLOCK)) 

def read_pack_header(src):    
    return unpack(EVB_PACK_HEADER, read_bytes_by_struct(src,EVB_PACK_HEADER))

def read_main_node(src):    
    return unpack(EVB_NODE_MAIN, read_bytes_by_struct(src,EVB_NODE_MAIN))

def pe_external_tree(fd):
    # Before calling, make sure cursor is already 
    # Both PE and external packages work with this method    
    hdr = read_pack_header(fd)
    assert hdr['signature'] == EVB_MAGIC, "Invalid singature"
    main_node = read_main_node(fd)    
    abs_offset = fd.tell() + main_node['size'] - 12 # offset from the head of the stream       
    fd.seek(-1,1)
    yield main_node
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
    hdr = read_pack_header(fd)
    assert hdr['signature'] == EVB_MAGIC, "Invalid singature"
    seek_origin = 0 
    while True:    
        seek_origin = fd.tell()
        try:
            header_node = read_header_node(fd)
            named_node = read_named_node(fd)
        except struct.error:
            return # Potential EOF exception  
        if   named_node['type'] == NODE_TYPE_FILE:
            fd.seek(seek_origin + header_node['size'] + 4 - get_size_by_struct(EVB_NODE_OPTIONAL_PE_FILE))
            optional_node = read_optional_legacy_pe_file_node(fd)                  
            optional_node['offset'] = fd.tell()
            fd.seek(optional_node['stored_size'],1)
        elif named_node['type'] == NODE_TYPE_FOLDER:
            optional_node = {}
            fd.seek(seek_origin + header_node['size'] + 4)
        elif named_node['type'] == NODE_TYPE_MAIN:        
            optional_node = {}    
            fd.seek(seek_origin + header_node['size'] + 4)            
        else:            
            return # assuming finished
        named_node['name'] = named_node['name'].decode('utf-16-le')        
        yield {**header_node,**named_node,**optional_node}       

def completed(generator):
    # Complete building the tree before we'd read the file
    for item in list(generator):        
        yield item

def process_file_node(fd,path,node):    
    with open(path,'wb') as output:                
        rsize = node['original_size']
        ssize = node['stored_size']
        offset = node['offset']
        fd.seek(offset)
        if rsize != ssize: # Compression detected                   
            chunks_blk = read_chunk_block(fd)                                                                             
            blkChunkData = fd.read(chunks_blk['size'] - get_size_by_struct(EVB_CHUNK_BLOCK))
            arrChunkData = (val for idx,val in enumerate(array.array('I',blkChunkData)) if idx % 3 == 0)
            # Chunk data comes in 12-bytes rotation: Chunk size (4bytes), Total size (4bytes), Padding (4bytes)
            # But with the last Chunk size, it does not come with Total size or Padding...
            # Thus filtering only every 3rd elements works. Which should always give us Chunk size
            # Even if the last 8 bytes is missing
            wsize = write_bytes(
                fd,output,
                size=ssize - chunks_blk['size'],
                chunk_sizes=arrChunkData,
                chunk_process=decompress,
                desc='Decompress [offset=0x%x, offsetBlk=0x%x]' % (fd.tell(),chunks_blk['size'])
            )
            assert wsize == rsize,"Incorrect size"
        else:            
            write_bytes(
                fd,output,
                size=ssize,
                desc='Write [size=0x%x, offset=0x%x]' % (ssize,offset)
            )

def restore_pe(file):
    from pefile import PE, OPTIONAL_HEADER_MAGIC_PE_PLUS
    pe = PE(file,fast_load=True)
    # Helpers    
    find_section = lambda name:next(filter(lambda x:name in x.Name,pe.sections))
    find_section_by_va = lambda rva:next(filter(lambda x:x.VirtualAddress == rva,pe.sections))
    find_data_directory = lambda name:next(filter(lambda x:name in x.name,pe.OPTIONAL_HEADER.DATA_DIRECTORY))    
    rva_from_va = lambda va:va - pe.OPTIONAL_HEADER.ImageBase
    raw_pointer_from_rva = lambda rva,section:rva - section.VirtualAddress + section.PointerToRawData
    # Trace and restore TLS Callback
    tls = find_data_directory('TLS')    
    tls_section = find_section_by_va(tls.VirtualAddress)
    tls_struct = unpack(
        TLS_DIRECTROY_PEPLUS if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS else TLS_DIRECTROY_PE,
        pe.__data__[tls_section.PointerToRawData:]
    )
    tls_callback = unpack(
        EVB_ENIGMA1_TLS_CALLBACK_PEPLUS if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS else EVB_ENIGMA1_TLS_CALLBACK_PE,
        pe.__data__[raw_pointer_from_rva(rva_from_va(tls_struct['AddressOfCallbacks']),tls_section):]
    )    
    tls_struct = pack(
        TLS_DIRECTROY_PEPLUS if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS else TLS_DIRECTROY_PE,
        *tls_struct.values()
    )
    # Remove .enigma sections
    pe.__data__ = pe.__data__[:find_section(b'.enigma1').PointerToRawData]
    pe.FILE_HEADER.NumberOfSections -= 2
    # Write to new file
    pe_name = os.path.basename(file)[:-4] + ORIGINAL_PE_SUFFIX
    pe_name = os.path.join(output,pe_name).replace('\\','/')
    pe.write(pe_name)
    print('[-] Original PE saved:',pe_name)

def seek_to_magic(fd,magic):    
    with mmap(fd.fileno(),length=0,access=ACCESS_READ) as mm:
        result = mm.find(magic)
        if result < 0: return False
        print('[-] Found magic at',hex(result))    
    fd.seek(result)
    return result

if __name__ == "__main__":
    parser = ArgumentParser(description='Enigma Vitural Box Unpacker')
    parser.add_argument('--ignore-fs',help='Don\'t extract virtual filesystem. Useful if you want the PE only',action='store_true',default=False)
    parser.add_argument('--ignore-pe',help='Treat PE files like external packages and thereby does not recover the original executable (for usage without pefile)',default=False)
    parser.add_argument('--legacy',help='Enable compatibility mode to work with older (6.x) EVB packages',action='store_true',default=False)
    parser.add_argument('--list',help='Don\'t extract the files and print the TOC only (surpresses other output)',action='store_true',default=False)
    parser.add_argument('file', help='File to be unpacked')
    parser.add_argument('output', help='Extract destination directory')
    args = parser.parse_args()    
    sys.stdout = sys.stderr
    # Redirect logs to stderr
    file, output ,ignore_fs, ignore_pe,legacy , list_files_only = args.file, args.output ,args.ignore_fs, args.ignore_pe , args.legacy , args.list
    if list_files_only:
        print = lambda *a,**k:None
    print('Enigma Virtual Box Unpacker v%s' % __version__)
    # Preparing base path
    os.makedirs(output,exist_ok=True)    
    if ignore_pe:
        print('[!] Skipping PE restoration')
    if ignore_fs:
        print('[!] Skipping virtual FS extraction')
    if legacy:
        print('[!] Legacy mode enabled')
  
    with open(file,'rb') as fd:
        # Locate magic
        hdr = fd.read(2)        
        if hdr == b'MZ' and not ignore_pe and not list_files_only:
            # Depack PEs
            restore_pe(file)
        if ignore_fs:
            sys.exit(0)
        # Dump EVB content
        print('[-] Searching for magic')
        magic = seek_to_magic(open(file,'rb'),EVB_MAGIC)
        # I was having really weird issues with mmap on my machine, aleast in python,
        # FileIO will report `-8192` for `tell()` or `seek(0,1)` once mmap is attached to its `fileno`
        # Alas, acquiring a handle seem to fix the issue. But it would be really nice if someone could tell me
        # what is going on here
        assert not magic is False, "Magic not found"          
        fd.seek(magic)
        if legacy:
            nodes = completed(legacy_pe_tree(fd))
        else:
            nodes = completed(pe_external_tree(fd))
        # Traversing nodes
        last_stack = dict()
        def get_prefix(level):
            prefix = '└───' if last_stack[level] else '├───'
            for _ in range(level,0,-1):
                if _ != 0:
                    if not last_stack[_ - 1]:
                        prefix = '│   '+prefix
                    else:
                        prefix = '    '+prefix
            return prefix
        def traverse_next_node(node,path_prefix=output,level=0):                        
            if level == 0 and node['type'] == NODE_TYPE_FOLDER:
                node['name'] = FOLDER_ALTNAMES.get(node['name'],node['name'])                
            path = os.path.join(path_prefix,node['name']).replace('\\','/')
            sys.stderr.write('   ' + get_prefix(level) + ' ' + path + '\n')
            if node['type'] == NODE_TYPE_FILE:
                if not list_files_only:
                    process_file_node(fd,path,node)
            elif node['type'] == NODE_TYPE_FOLDER:
                if not os.path.isdir(path):
                    os.makedirs(path)
                for _ in range(0,node['objects_count']):
                    last = _ == node['objects_count'] - 1
                    last_stack[level + 1] = last
                    traverse_next_node(next(nodes),path_prefix=path,level=level + 1)        
        try:            
            main_node = next(nodes)
            sys.stderr.write('[Virtual Box Filetable]\n')
            sys.stderr.flush()
            for _ in range(main_node['objects_count']):
                last = _ == main_node['objects_count'] - 1
                last_stack[0] = last                
                traverse_next_node(next(nodes))
        except StopIteration:                
            print('[!] Magic found. But no filetable can be extracted.')
            print('[!] Try enable / disabling --legacy option to see if that works.')      
            sys.exit(1)
        except AssertionError as e:
            print('[!] While extracting package',e)
            sys.exit(1)
        print('[!] Extraction complete',' ' * 20)
        sys.exit(0)
