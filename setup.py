import setuptools,evbunpack

with open("README.md", "r",encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name="evbunpack",
    version=evbunpack.__version__,
    author=evbunpack.__author__,
    author_email="greats3an@gmail.com",
    description="Enigma Virtual Box Unpacker / 解包工具",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mos9527/evbunpack",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "pefile"
    ],
    entry_points={"console_scripts": ["evbunpack=evbunpack.__main__:__main__"]},
    python_requires='>=3.0',
)