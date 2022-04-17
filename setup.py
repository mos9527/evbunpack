import setuptools,evbunpack

with open("README.md", "r",encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name="evbunpack",
    version=evbunpack.__version__,
    author=evbunpack.__author__,
    author_email="greats3an@gmail.com",
    description="Enigma Virtual Box 解包工具",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/greats3an/evbunpack",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],install_requires=[],
    python_requires='>=3.0',
)