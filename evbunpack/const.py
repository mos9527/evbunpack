#-*- coding: utf-8 --
EVB_PACK_HEADER = [
    ('4s', 'signature'),   # Would always be ('EVB\x00') if valid
    64
]

EVB_CHUNK_BLOCK = [
    ('I','size'),
    ('I',''),    
    8
]

EVB_HEADER_NODE = [
    ('I','size'),
    ('8s',''),
    ('I','objects_count'),
    16
]

EVB_NODE_MAIN = [
    ('I', 'size'),
    ('6s', ''), # don't know what this is for
    ('I', 'objects_count'),
    14
]

EVB_NODE_NAMED = [    
    ('%ds', 'name'), # args[0] - filename buffer length
    ('2s', ''),
    ('B', 'type'),
    3  # the length of the 2s + type
]

EVB_NODE_OPTIONAL_FILE = [
    ('2s', ''),
    ('I', 'original_size'),
    ('4s',''),
    ('24s','filetime'),
    ('15s',''),
    ('I', 'stored_size'),
    53
]

EVB_NODE_OPTIONAL_PE_FILE = [
    ('2s', ''),
    ('I', 'original_size'),
    ('4s',''),
    ('24s','filetime'),
    ('7s',''),
    ('I', 'stored_size'),
    ('4s',''),
    49 
]

NODE_TYPE_MAIN   = 0
NODE_TYPE_FILE   = 2
NODE_TYPE_FOLDER = 3