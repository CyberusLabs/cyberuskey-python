import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="cyberuskey-bkozub", # Replace with your own username
    version="0.0.2",
    author="CyberusLabs sp.z.o.o.",
    author_email="support@cyberuslabs.com",
    description="Cyberus Key authenticate library",
    long_description=long_description,
    url="https://github.com/CyberusLabs/cyberuskey-python",
    packages=setuptools.find_packages(),
    install_requires=["requests>=2.23.0", "PyJWT >= 1.7.1", "cryptography>=2.9.2"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)

