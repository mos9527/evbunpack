from argparse import ArgumentParser
from __const__ import *
import struct
import io,os,math

def SerialUnpack(packHeader, buffer, *args):
    '''Utility function - used to unpack files'''
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
            pak['name'] = pak['name'].decode()  # decode the filename
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

        nNode = readNamedNode()
        oNode = readOptionalNode(nNode)
        # read all nodes
        if nNode and oNode:
            yield {**nNode, **oNode}
        else:
            return  # stop when no more items are available

if __name__ == "__main__":
    parser = ArgumentParser(description='Enigma Vitural Box external package unpacker')
    parser.add_argument('file', help='EVB external package (container)')
    parser.add_argument('output', help='The desirerd output path')
    args = parser.parse_args()

    file, output = args.file, args.output
    fp = open(file, 'rb')
    evbHeader,mainNode = ReadEVBMeta(fp)

    nodes = GenerateEVBNodes(mainNode)
    # defining some useful tools
    jstr = lambda s:str(s).center(8)[:8]
    hrs  = lambda s:f"{int(s/(1024**int(math.log2(s) // 10)))} {['B', 'kB', 'MB', 'GB', 'TB'][int(math.log2(s) // 10)]}" # one-line for byte hrs?hell yea
    # start traversing
    def traverse(node,prefix=output,level=0):
        path = os.path.join(prefix,node['name'])
        header = f"│{'─' * level} {path}"
        if node['type'] == NODE_TYPE_FILE:
            size = node['stored_size']
            open(path,'wb').write(fp.read(size))
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