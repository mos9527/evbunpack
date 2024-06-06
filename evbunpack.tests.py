import unittest, os, logging
from evbunpack.__main__ import main
try:
    import coloredlogs
    coloredlogs.install(level='DEBUG')
except ImportError:
    logging.basicConfig(level=logging.DEBUG)
os.chdir(os.path.join(os.path.dirname(__file__),'tests'))

TEMP_OUTPUT_FILENAME = '_unpacked.exe'
def test_unpack_exec(pe_file):
    main(pe_file, 'output', os.path.join('.',TEMP_OUTPUT_FILENAME))
    return_code = os.system(TEMP_OUTPUT_FILENAME) 
    if return_code != 0:
        logging.error('Failed to execute unpacked file. Exit code: %d', return_code)
    return return_code

# class Unpack_10_70_x64(unittest.TestCase):
#     def test(self):
#         assert test_unpack_exec('x64_PackerTestApp_packed_20240522.exe') == 0

# class Unpack_7_80_x64(unittest.TestCase):
#     def test(self):
#         assert test_unpack_exec('x64_PackerTestApp_packed_20170713.exe') == 0

# class Unpack_10_70_x86(unittest.TestCase):
#     def test(self):
#         assert test_unpack_exec('x86_PackerTestApp_packed_20240522.exe') == 0


class Unpack_7_80_x86(unittest.TestCase):
    def test(self):
        assert test_unpack_exec('x86_PackerTestApp_packed_20170713.exe') == 0

if __name__ == '__main__':
    unittest.main()