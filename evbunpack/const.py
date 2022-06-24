#-*- coding: utf-8 --
EVB_MAGIC = b'EVB\x00'

EVB_PACK_HEADER = [
    ('4s', 'signature'),   # Would always be ('EVB\x00') if valid
    ('60s',''),    
]

EVB_CHUNK_BLOCK = [
    ('I','size'),
    ('I',''),    
]

EVB_HEADER_NODE = [
    ('I','size'),
    ('8s',''),
    ('I','objects_count'),
]

EVB_NODE_MAIN = [
    ('I', 'size'),
    ('8s', ''),
    ('I', 'objects_count'),
]

EVB_NODE_NAMED = [    
    ('%ds', 'name'), # args[0] - filename buffer length
    ('2s', ''),
    ('B', 'type'),
]

EVB_NODE_OPTIONAL_FILE = [
    ('2s', ''),
    ('I', 'original_size'),
    ('4s',''),
    ('8s','filetime1'),
    ('8s','filetime2'),
    ('8s','filetime3'),
    ('15s',''),
    ('I', 'stored_size'),
]

EVB_NODE_OPTIONAL_PE_FILE = [
    ('2s', ''),
    ('I', 'original_size'),
    ('4s',''),
    ('8s','filetime1'),
    ('8s','filetime2'),
    ('8s','filetime3'),
    ('7s',''),
    ('I', 'stored_size'),
    ('4s',''),
]

NODE_TYPE_MAIN   = 0
NODE_TYPE_FILE   = 2
NODE_TYPE_FOLDER = 3