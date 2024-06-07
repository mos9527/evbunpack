#-*- coding: utf-8 --
EVB_MAGIC = b'EVB\x00'


PE_EXCEPTION = [
    ('I','BEGIN_ADDRESS'),
    ('I','END_ADDRESS'),
    ('I','HANDLER_PTR'),  
    ('I','HANDLER_DATA'),  
    ('I','PROLOG_ADDRESS'),          
]

PE64_EXCEPTION = [
    ('I','BEGIN_ADDRESS'),
    ('I','END_ADDRESS'),
    ('I','UNWIND_INFO'),    
]

class EVB_ENIGMA1_HEADER:
    x64_NEW = [
        # TLS (first 32 bytes of it if there is any)
        ('32s', 'TLS'),
        # Padding Begin
        ('Q', ''), ('Q', ''),
        ('Q', ''), ('Q', ''), 
        ('Q', ''), ('Q', ''), 
        ('Q', ''), 
        # Padding End   
        ('Q', 'UNK_1'),
        ('Q', ''), ('Q', ''),
        ('Q', ''),
        ('I','IMPORT_ADDRESS'),
        ('I','IMPORT_SIZE'),
        ('I','RELOC_ADDRESS'),
        ('I','RELOC_SIZE'),
        ('I','TLS_ADDRESS'),
        ('I','TLS_SIZE'),    
    ]

    x64_OLD = [
        # TLS (first 32 bytes of it if there is any)
        ('32s', 'TLS'),
        # Padding Begin
        ('Q', ''), ('Q', ''),
        ('Q', ''), ('Q', ''), 
        ('Q', ''), ('Q', ''), 
        ('Q', ''), 
        # Padding End   
        ('Q', 'UNK_1'),
        ('Q', ''),
        ('I','IMPORT_ADDRESS'),
        ('I','IMPORT_SIZE'),
        ('I','RELOC_ADDRESS'),
        ('I','RELOC_SIZE'),
        ('I','TLS_ADDRESS'),
        ('I','TLS_SIZE'),    
    ]

    x86_NEW = [
        # TLS (first 16 bytes of it if there is any)
        ('16s', 'TLS'),
        # Padding Begin
        ('Q', ''), ('Q', ''),
        ('Q', ''), ('Q', ''), 
        ('Q', ''), ('Q', ''), 
        # Padding End   
        ('Q', 'UNK_1'), ('Q', 'UNK_2'),
        ('I', 'UNK_3'),
        ('I','IMPORT_ADDRESS'),
        ('I','IMPORT_SIZE'),
        ('I','RELOC_ADDRESS'),
        ('I','RELOC_SIZE'),
        ('I','TLS_ADDRESS'),
        ('I','TLS_SIZE'),
    ]

    x86_OLD = [
        # TLS (first 16 bytes of it if there is any)
        ('16s', 'TLS'),
        # Padding Begin
        ('Q', ''), ('Q', ''),
        ('Q', ''), ('Q', ''), 
        ('Q', ''), ('Q', ''), 
        # Padding End   
        ('Q', 'UNK_1'),
        ('I', 'UNK_3'),
        ('I','IMPORT_ADDRESS'),
        ('I','IMPORT_SIZE'),
        ('I','RELOC_ADDRESS'),
        ('I','RELOC_SIZE'),
        ('I','TLS_ADDRESS'),
        ('I','TLS_SIZE'), 
    ]
    @staticmethod
    def get_struct(arch_64 : bool, legacy_pe : bool):
        if arch_64:
            return EVB_ENIGMA1_HEADER.x64_OLD if legacy_pe else EVB_ENIGMA1_HEADER.x64_NEW
        else:
            return EVB_ENIGMA1_HEADER.x86_OLD if legacy_pe else EVB_ENIGMA1_HEADER.x86_NEW

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