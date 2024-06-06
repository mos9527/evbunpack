#-*- coding: utf-8 -*-
# Copy
from itertools import dropwhile
import struct,os,array,sys, logging
from argparse import ArgumentParser
from mmap import mmap,ACCESS_READ
from io import BytesIO
from evbunpack.aplib import decompress
from evbunpack.const import *
from evbunpack import __version__
logger = logging.getLogger('evbunpack')

FOLDER_ALTNAMES = {
    '%DEFAULT FOLDER%' : ''
}

def write_bytes(fd,out_fd,size,chunk_sizes=None,chunk_process=None,default_chunksize=65536,desc='Extracting...'):
    bytes_read  = 0
    bytes_wrote = 0
    inital_offset = fd.tell()
    while bytes_read < size:
        sys.stderr.write('%s: total=%8xh read=%8xh\r' % (desc,size,bytes_read))
        chunk_size = next(chunk_sizes) if chunk_sizes else default_chunksize        
        size_to_read = min(chunk_size,size - (fd.tell() - inital_offset))
        chunk = fd.read(size_to_read)
        bytes_read += len(chunk)
        chunk = chunk if not chunk_process else chunk_process(chunk)                
        bytes_wrote += out_fd.write(chunk)
    sys.stderr.write('\n')
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
    while (p[0]!=0 or p[1]!=0):
        blkFilename.extend(p)
        p = src.read(2)              
    block = blkFilename + src.read(1)
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
    # Before calling, make sure cursor is already at where
    # the following bytes are b`EVB\x00`
    # Both PE and external packages work with this method    
    hdr = read_pack_header(fd)
    assert hdr['signature'] == EVB_MAGIC, "Invalid signature"
    main_node = read_main_node(fd)    
    abs_offset = fd.tell() + main_node['size'] - 12 # offset from the head of the stream       
    fd.seek(-1,1)
    yield main_node
    max_object_count = 0
    current_object_count = 0
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
            current_object_count += 1      
        elif named_node['type'] == NODE_TYPE_FOLDER:
            optional_node = {}
            fd.seek(25,1)            
            max_object_count += header_node['objects_count']
            current_object_count += 1
        else:            
            return # assuming finished
        named_node['name'] = named_node['name'].decode('utf-16-le')        
        yield {**header_node,**named_node,**optional_node}
        if current_object_count > max_object_count  and max_object_count > 0:
            return        

def legacy_pe_tree(fd):
    # Older executables has their file table and content placed together
    # Courtesy of evb-extractor!    
    hdr = read_pack_header(fd)
    assert hdr['signature'] == EVB_MAGIC, "Invalid signature"
    seek_origin = 0 
    max_object_count = 0
    current_object_count = 0
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
            current_object_count += 1
        elif named_node['type'] == NODE_TYPE_FOLDER:
            optional_node = {}
            fd.seek(seek_origin + header_node['size'] + 4)
            max_object_count += header_node['objects_count']
            current_object_count += 1
        elif named_node['type'] == NODE_TYPE_MAIN:        
            optional_node = {}    
            fd.seek(seek_origin + header_node['size'] + 4)            
        else:            
            return # assuming finished
        named_node['name'] = named_node['name'].decode('utf-16-le')        
        yield {**header_node,**named_node,**optional_node}       
        if current_object_count > max_object_count and max_object_count > 0:
            return        

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
                desc='Decompressing File [offset=0x%x, offsetBlk=0x%x]' % (fd.tell(),chunks_blk['size'])
            )
            assert wsize == rsize,"Incorrect size"
        else:            
            write_bytes(
                fd,output,
                size=ssize,
                desc='Writing File [size=0x%x, offset=0x%x]' % (ssize,offset)
            )

def restore_pe(input_file : str, output_file : str, legcay_pe : bool):
    warnings_issued = 0

    from pefile import PE,OPTIONAL_HEADER_MAGIC_PE_PLUS
    logger.debug('Loading PE...')
    pe = PE(input_file,fast_load=True)
    arch_64 = pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS
    pe.__data__ = bytearray(pe.__data__) # This allows us to apply slicing on the PE data
    # Helpers    
    find_section = lambda name:next(filter(lambda x:name in x.Name,pe.sections))
    find_data_directory = lambda name:next(filter(lambda x:name in x.name,pe.OPTIONAL_HEADER.DATA_DIRECTORY))    
    search_pattern_in_sections = lambda pattern:next(dropwhile(lambda x: x[1] == -1, ((section, pe.__data__.find(pattern,section.PointerToRawData, section.PointerToRawData + section.SizeOfRawData)) for section in pe.sections)))
    # Data
    enigma1 = pe.__data__[find_section(b'.enigma1').PointerToRawData:]
    hdr = unpack(EVB_ENIGMA1_HEADER.get_struct(arch_64, legcay_pe), enigma1)
    # Restore section with built-in offsets. All these ADDRESSes are VAs
    find_data_directory('IMPORT').VirtualAddress = hdr['IMPORT_ADDRESS']
    find_data_directory('IMPORT').Size = hdr['IMPORT_SIZE']
    find_data_directory('RELOC').VirtualAddress = hdr['RELOC_ADDRESS']
    find_data_directory('RELOC').Size = hdr['RELOC_SIZE']
    logger.debug('Import -> VA=0x%x Size=0x%x' % (hdr['IMPORT_ADDRESS'],hdr['IMPORT_SIZE']))
    logger.debug('Reloc  -> VA=0x%x Size=0x%x' % (hdr['RELOC_ADDRESS'],hdr['RELOC_SIZE']))
    logger.debug('Rebuilding Exception directory...')
    # Rebuild the exception directory
    exception_dir = find_data_directory('EXCEPTION')    
    exception_raw_ptr = pe.get_offset_from_rva(exception_dir.VirtualAddress)
    exception_data = pe.__data__[exception_raw_ptr:exception_raw_ptr + exception_dir.Size]    
    exception_struct = PE64_EXCEPTION if arch_64 else PE_EXCEPTION
    exception_end = 0
    for i in range(0,exception_dir.Size,get_size_by_struct(exception_struct)):
        block = unpack(exception_struct,exception_data[i:])
        block['section'] = pe.get_section_by_rva(block['BEGIN_ADDRESS'])
        exception_end = i
        if b'.enigma' in block['section'].Name: 
            break
    exception_data = exception_data[:exception_end]
    # Destory .enigma* sections
    pe.__data__ = pe.__data__[:find_section(b'.enigma1').PointerToRawData] + pe.__data__[find_section(b'.enigma2').PointerToRawData + find_section(b'.enigma2').SizeOfRawData:]
    # If original program has a overlay, this will perserve it. Otherwise it's okay to remove them anyway.
    assert pe.sections.pop().Name == b'.enigma2'
    assert pe.sections.pop().Name == b'.enigma1'
    pe.FILE_HEADER.NumberOfSections -= 2    
    # NOTE: .enigma1 contains the VFS, as well as some Optional PE Header info as descrbied above
    # NOTE: .enigma2 is a aplib compressed loader DLL. You can decompress it with aplib provided in this repo  
    # Append the exception section and assign the pointers
    if (exception_data):
        # Reassign the RVA & sizes    
        logger.debug('Rebuilt Exception directory. Size=0x%x' % len(exception_data))
        # Find where this could be placed at...since EVB clears the original exception directory listings
        # PEs with overlays won't work at all if EVB packed them.
        # We must remove the sections and do NOT append anything new
        try:
            section, offset = search_pattern_in_sections(b'\x00' * len(exception_data))
            logger.debug('Found suitable section to place Exception Directory. Name=%s RVA=0x%x' % (section.Name.decode(),offset - section.PointerToRawData))
            pe.__data__[offset:offset+len(exception_data)] = exception_data
            section.SizeOfRawData = max(section.SizeOfRawData,len(exception_data))
            exception_dir.VirtualAddress = pe.get_rva_from_offset(offset)
            exception_dir.Size = len(exception_data)
        except StopIteration as e:
            logger.warning('Cannot place Exception Directory. It\'s highly likely that the unpacked PE won\'t work.')
            warnings_issued += 1
            exception_dir.VirtualAddress = 0
            exception_dir.Size = 0
    else:
        logger.debug('Original program does not contain Exception Directory.')
        exception_dir.VirtualAddress = 0
        exception_dir.Size = 0
    # Serach for TLS in memory map since it's copied to the header
    tls_dir = find_data_directory('TLS')
    try:
        tls_data = hdr['TLS']
        section, offset = search_pattern_in_sections(tls_data[:12])
        logger.debug('TLS Directory found. Offset=0x%x Section=%s' % (offset,section.Name.decode()))
        tls_dir.VirtualAddress = pe.get_rva_from_offset(offset)
        tls_dir.Size = 40 if arch_64 else 24
    except StopIteration as e:
        logger.warning('TLS Directory not found. Original program may not have TLS data or the packer header is incorrectly parsed.')
        warnings_issued += 1
        tls_dir.VirtualAddress = 0
        tls_dir.Size = 0
    # Write to new file
    new_file_data = pe.write()
    with open(output_file,'wb+') as f:
        write_bytes(BytesIO(new_file_data),f,len(new_file_data),desc='Saving PE')
    logger.info('Original PE saved: %s' % output_file)
    if warnings_issued:
        logger.warning('There were %d warning(s) issued during the restoration process.' % warnings_issued)
        logger.warning('Please try toggling the --legacy-pe flag if the unpacked executable appears corrupt.')        

def search_for_magic(fd,size,magic):
    CHUNKSIZE = 16 * 2**20  # 16MB
    for i in range(0,size,CHUNKSIZE):
        with mmap(fd.fileno(),offset=i,length=min(CHUNKSIZE,size - i),access=ACCESS_READ) as mm:
            result = mm.find(magic)
            if result >= 0:
                logger.debug('Found magic at %x' % result)
                return result
    return -1

def unpack_files(file : str, out_dir : str, legacy_fs : bool, listing_only : bool):
    size = os.stat(file).st_size
    magic = search_for_magic(fd,size,EVB_MAGIC)
    assert magic >= 0, "EVB filesystem magic not found. Cannot proceed."
    with open(file,'rb') as fd:               
        fd.seek(magic)
        if legacy_fs:
            nodes = completed(legacy_pe_tree(fd))
        else:
            nodes = completed(pe_external_tree(fd))
        depths = dict()
        def get_prefix(level):
            prefix = '└───' if depths[level] else '├───'
            for _ in range(level,0,-1):
                if _ != 0: prefix = '│   ' if not depths[_ - 1] else '    ' +prefix
            return prefix
        def traverse_next_node(node,pfx=out_dir,depth=0):                        
            if node['type'] == NODE_TYPE_FOLDER:
                node['name'] = FOLDER_ALTNAMES.get(node['name'],node['name'])                
            assert ('\\' not in node['name']) and ('/' not in node['name']) and (':' not in node['name']), f'Invalid character in node name: {node["name"]}'
            assert node['name'] != '..' and node['name'] != '.', 'node name cannot be either . or ..'
            path = os.path.normpath(os.path.join(pfx,node['name'])).replace('\\','/')
            sys.stderr.write('   ' + get_prefix(depth) + ' ' + path + '\n')
            if node['type'] == NODE_TYPE_FILE and not listing_only:
                process_file_node(fd,path,node)
            elif node['type'] == NODE_TYPE_FOLDER:
                if not os.path.isdir(path) and not listing_only:
                    os.makedirs(path)
                for _ in range(0,node['objects_count']):
                    last = _ == node['objects_count'] - 1
                    depths[depth + 1] = last
                    traverse_next_node(next(nodes),pfx=path,depth=depth + 1) 
        try:
            main_node = next(nodes)
            for _ in range(main_node['objects_count']):     
                traverse_next_node(next(nodes))
        except StopIteration:                
            logger.error('The filetable appears to be corrupted. Cannot proceed any further.')
            logger.error('Please try toggling the --legacy-fs flag to solve this issue.')
            return
        except AssertionError as e:
            logger.error('While extracting package %s' % e)
            return
        logger.info('Extraction complete')
        return
    
def main(file : str, out_dir : str = '.', out_pe : str = '', ignore_fs: bool = False, ignore_pe: bool  = False, legacy: bool = False, list_files_only: bool = False):
    logger.info('Enigma Virtual Box Unpacker v%s' % __version__)
    # Preparing base path
    os.makedirs(out_dir,exist_ok=True)    
    if ignore_pe:
        logger.warning('Skipping PE restoration')
    if ignore_fs:
        logger.warning('Skipping virtual FS extraction')
    if legacy:
        logger.warning('Legacy mode override enabled')

    with open(file,'rb') as fd:
        # Locate magic
        hdr = fd.read(2)        
        if hdr == b'MZ' and not ignore_pe and not list_files_only:
            # Depack PEs
            if not out_pe:
                out_pe = os.path.join(out_dir, os.path.basename(file))
                logger.warning('Using default executable save path: %s' % out_pe)
            os.makedirs(os.path.dirname(out_pe), exist_ok=True)
            restore_pe(file,out_pe)
        if ignore_fs:
            return 0
        # Dump EVB content
        fd.seek(0)
        logger.debug('Searching for magic')
        size = os.stat(file).st_size
        magic = search_for_magic(fd,size,EVB_MAGIC)
        assert not magic is False, "Magic not found"

def __main__():
    parser = ArgumentParser(description='Enigma Virtual Box Unpacker')
    group = parser.add_argument_group('Flags')
    group.add_argument('--ignore-fs',help='Don\'t extract virtual filesystem. Useful if you want the PE only',action='store_true',default=False)
    group.add_argument('--ignore-pe',help='Treat PE files like external packages and thereby does not recover the original executable (for usage without pefile)',default=False)
    group.add_argument('--legacy',help='Enable compatibility mode to work with older (6.x) EVB packages',action='store_true',default=False)
    group.add_argument('--list',help='Don\'t extract the files and print the TOC only (surpresses other output)',action='store_true',default=False)
    group.add_argument('--log-level',help='Set log level',default='INFO',choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'])
    group = parser.add_argument_group('Output')
    group.add_argument('--out-dir', help='Output folder',default='.')
    group.add_argument('--out-pe', help='(If PE file is recovered) Where the unpacked exe is saved. Leave empty to save it in the output folder.',default='')
    group = parser.add_argument_group('Input')
    group.add_argument('file', help='File to be unpacked')
    args = parser.parse_args()    
    logging.basicConfig(level=args.log_level)
    sys.exit(main(args.file,args.out_dir,args.out_pe,args.ignore_fs,args.ignore_pe,args.legacy,args.list))

if __name__ == "__main__":
    __main__()