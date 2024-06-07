import os, logging
logging.basicConfig(level=logging.DEBUG)
os.chdir(os.path.join(os.path.dirname(__file__),'tests'))

TEMP_OUTPUT_FILENAME = '_unpacked.exe'
def unpack_exec(pe_file, **kw):
    from evbunpack.__main__ import main
    main(pe_file, 'output', os.path.join('.',TEMP_OUTPUT_FILENAME), **kw)
    return_code = os.system(TEMP_OUTPUT_FILENAME) 
    if return_code != 0:
        logging.error('Failed to execute unpacked file. Exit code: %d', return_code)
    return return_code

def test_unpack10_70_x64():
    assert unpack_exec('x64_PackerTestApp_packed_20240522.exe', legacy_fs = False, legacy_pe = False) == 0

def test_unpack7_80_x64():
    assert unpack_exec('x64_PackerTestApp_packed_20170713.exe', legacy_fs = True, legacy_pe = True) == 0

def test_unpack10_70_x86():
    assert unpack_exec('x86_PackerTestApp_packed_20240522.exe', legacy_fs = False, legacy_pe = False) == 0

def test_unpack7_80_x86():
    assert unpack_exec('x86_PackerTestApp_packed_20170713.exe', legacy_fs = True, legacy_pe = True) == 0
