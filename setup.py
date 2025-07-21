from setuptools import setup, find_packages

setup(
    name='whiterabbit',
    version='0.1.0',
    description='Secure file laundering and obfuscation library',
    author='Miscreant',
    author_email='aMiscreant@protonmail.com',
    url='https://github.com/amiscreant/whiterabbit',
    packages=find_packages(),
    python_requires='>=3.8',
    install_requires=[
        'Pillow',         # for image processing
        'piexif',         # add your dependencies here
        'numpy',
        'cryptography',
        'requests',
        'flask',
    ],
    entry_points={
        'console_scripts': [
            'whiterabbit=whiterabbit.main:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
)
