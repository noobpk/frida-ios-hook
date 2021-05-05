import setuptools

with open ("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='Frida iOS Hook',
    version='3.4',
    description='Trace Class/Func & Modify Return Value',
    author='noobpk',
    author_email='ltp.noobpk@gmail.com',
    long_description =long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/noobpk/frida-ios-hook/',
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent"

    ],
    python_requires='>=3.0'
)
