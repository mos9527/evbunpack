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
    x64 = {
        '10_70':[
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
        ],
        '9_70':[
            ('32s', 'TLS'),
            # Padding Begin
            ('Q', ''), ('Q', ''),
            ('Q', ''), ('Q', ''), 
            ('Q', ''), ('Q', ''), 
            ('Q', ''), 
            ('I', ''),
            # Padding End              
            ('Q', 'UNK_1'),
            ('Q', ''),
            ('I','IMPORT_ADDRESS'),
            ('I','IMPORT_SIZE'),
            ('I','RELOC_ADDRESS'),
            ('I','RELOC_SIZE'),
            ('I','TLS_ADDRESS'),
            ('I','TLS_SIZE'),        
        ],        
        '7_80':[
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
    }

    x86 = {
        '10_70':[
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
        ],
        '9_70' : [
            ('16s', 'TLS'),
            # Padding Begin
            ('Q', ''), ('Q', ''),
            ('Q', ''), ('Q', ''), 
            ('Q', ''), ('Q', ''), 
            # Padding End   
            ('Q', 'UNK_1'), ('Q', 'UNK_2'),            
            ('I','IMPORT_ADDRESS'),
            ('I','IMPORT_SIZE'),
            ('I','RELOC_ADDRESS'),
            ('I','RELOC_SIZE'),
            ('I','TLS_ADDRESS'),
            ('I','TLS_SIZE'), 
        ],        
        '7_80' : [
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
    }
    @staticmethod
    def get_options():
        return list(EVB_ENIGMA1_HEADER.x86.keys())

    @staticmethod
    def get_struct(arch_64 : bool, key : str):
        if arch_64:
            return EVB_ENIGMA1_HEADER.x64[key]
        else:
            return EVB_ENIGMA1_HEADER.x86[key]

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