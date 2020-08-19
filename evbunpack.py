from argparse import ArgumentParser
from __const__ import *
import struct,sys,io,os,math,datetime
blocksize = 8 * 1024 ** 2 # 8 MB per block
def SerialUnpack(packHeader, buffer, *args):
    '''Utility function - used to unpack array of bytes'''
    if not isinstance(packHeader, list):
        packHeader = [packHeader]
    # ignore non-tuple items
    fmt, desc = zip(*[p for p in packHeader if isinstance(p, tuple)])
    # unzips format and description
    fmt_all = f'<{"".join(fmt)}' % args
    unpacked = struct.unpack_from(fmt_all, buffer, 0)
    return dict({k: v for k, v in zip(desc, unpacked) if k})

def ReadEVBMeta(fp : io.BufferedIOBase): 
    '''Reads current container\'s "meta" elements,seek to where the raw data begins

       Returns the read `(EVB_PACK_HEADER,EVB_NODE_MAIN)` object
    '''
    evbHeader = SerialUnpack(EVB_PACK_HEADER, fp.read(64))
    assert evbHeader['signature'] == b'EVB\x00'
    # perform the magic check
    mainNode = SerialUnpack(EVB_NODE_MAIN, fp.read(16))
    # read the folder descriptor
    fp.read(11)  # skip 11 pad bytes
    mainNode['data'] = fp.read(mainNode['size'] - 16 - 11) # appends main node data
    fp.read(4)
    return evbHeader,mainNode

def GenerateEVBNodes(mainNode):
    '''Generating nodes within the container

       EVB containers are readonly,thus the headers' sizes are fixed once generated
       We can see one as two region : Node region & Content region
       Each `node` has two sub nodes : 
        - Named node
            These contain the name,type for our nodes
        - "Optional" Node
            These contain the file sizes and etc 
    '''
    fp = io.BytesIO(mainNode['data'])  # streamify IO for cleaner logic
    bound = len(mainNode['data'])
    while True:
        def readNamedNode():
            fPre = fp.read(3) # pre - assigns object count
            def readFileName():
                filenameBuf = b''
                while fp.tell() + 2 < bound:  # read until we are at the end of the header
                    p = struct.unpack('2c', fp.read(2))
                    if p[1] == b'\x00':  # eof
                        # return to the position where we last read
                        fp.seek(-2, 1)
                        return filenameBuf
                    else:
                        filenameBuf += p[1]
                return None
            fnBuf = readFileName()
            if not fnBuf:
                return None
            buf = fPre + fnBuf + fp.read(EVB_NODE_NAMED[-1])
            pak = SerialUnpack(EVB_NODE_NAMED, buf, len(fnBuf))
            return pak

        def readOptionalNode(nNode):
            if not nNode:
                return None
            nodeSelection = {
                NODE_TYPE_FILE    :  EVB_NODE_OPTIONAL_FILE,
                NODE_TYPE_FOLDER  :  EVB_NODE_OPTIONAL_FOLDER
            }
            nodeStruct = nodeSelection[nNode['type']]
            buf = fp.read(nodeStruct[-1])
            if nNode['type'] == NODE_TYPE_FILE:
                # optioal padding for file nodes
                if fp.tell() + 12 < bound:
                    fp.read(12)
            pak = SerialUnpack(nodeStruct, buf)
            return pak
        def decodeNode(nNode,oNode):
            if nNode and oNode:
                node = {**nNode, **oNode}
                keys = {
                    'name':lambda v:v.decode(),
                    'created_time':lambda v:datetime.datetime.fromtimestamp(v),
                    'reserved':lambda v:' '.join([hex(n)[2:].upper().rjust(2,'0') for n in v])
                }
                for k in keys:
                    if k in node.keys():
                        node[k] = keys[k](node[k])
                return node
            else:
                return None
        nNode = readNamedNode()
        oNode = readOptionalNode(nNode)
        node = decodeNode(nNode,oNode)
        # read all nodes
        if node:
            yield node
        else:
            return  # stop when no more items are available

if __name__ == "__main__":
    parser = ArgumentParser(description='Enigma Vitural Box external package unpacker')
    parser.add_argument('file', help='EVB external package (container)')
    parser.add_argument('output', help='The desirerd output path')
    args = parser.parse_args()

    file, output       = args.file, args.output
    evbHeader,mainNode = None,None 
    fp = open(file, 'rb')
    try:
        evbHeader,mainNode = ReadEVBMeta(fp)
    except AssertionError:
        print( 'ERROR : File magic mismatch')
        print(r'Make sure that your file header begins with hexidecimal values of 0x45 0x56 0x42 0x00 (EVB\x00)')
        sys.exit(1)
    nodes = GenerateEVBNodes(mainNode)
    # defining some useful tools
    jstr = lambda s:str(s).center(16)[:16]
    hrs  = lambda s:f"{int(s/(1024**int(math.log2(s) // 10)))} {['B', 'kB', 'MB', 'GB', 'TB'][int(math.log2(s) // 10)]}" if s else "0 B" # one-line for byte hrs?hell yea
    # start traversing
    def traverse(node,prefix=output,level=0):
        path = os.path.join(prefix,node['name'])
        header = f"│{'─' * level} {path}"
        if node['type'] == NODE_TYPE_FILE:
            size = node['stored_size']
            # writing file
            with open(path,'wb') as file:
                b = 0
                for b in range(0,size,blocksize)[1:]:
                    precentage = int(b * 100 // size)
                    print(jstr(f'{precentage} % of {hrs(size)}'),header,end='\r')           
                    block = fp.read(blocksize)
                    file.write(block)                             
                file.write(fp.read(size - b)) # write whatever is left
            print(f'{jstr(hrs(size))} {header}')
        else:
            # dealing with folders
            if not os.path.isdir(path):os.makedirs(path)         
            print(f'{jstr("FOLDER")} {header}')
            for i in range(0,node['objects_count']):
                traverse(next(nodes),prefix=path,level=level + 1)
    print(f'Unpacking {file} -> {output}')
    print('─' * 50)
    traverse(next(nodes))