'''Constant values needed for unpacking'''
EVB_PACK_HEADER = [
    ('4s', 'signature'),   # Would always be ('EVB\x00') if valaid
    64
]

EVB_NODE_MAIN = [
    ('I', 'size'),
    ('8s', ''),
    ('I', 'objects_count'),
    16
]

EVB_NODE_NAMED = [
    ('H','objects_count'), # for non-folders,this value will remain 0
    ('c',''),
    ('%ds', 'name'),
    ('3s', ''),
    ('B', 'type'),
    4  # then length of the pad and the `type`
]

# there's a certain amount of pad bytes that's decided by `EVB_NODE_NAMED['type']`
# ...where when `type` is 3 (folder),the total bytes of the node is (40)

EVB_NODE_OPTIONAL_FOLDER = [
    ('37s', 'reserved'),
    37
]  # the optional node for folders are barely useful,so we'd drop them here

EVB_NODE_OPTIONAL_FILE = [
    ('2s', ''),
    ('I', 'original_size'),
    ('43s', ''),
    ('I', 'stored_size'),
    53
]
# ...where when `type` is 2 (file),the total bytes of the node is (53) with
#  additional 15 bytes of pad (unless the file is the last one on the list)

NODE_TYPE_FILE   = 2
NODE_TYPE_FOLDER = 3
