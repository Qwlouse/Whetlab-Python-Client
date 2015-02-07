# To upload:
# First make sure you've created a ~.pypirc file
# a la http://peterdowns.com/posts/first-time-with-pypi.html
# Then:
# python setup.py sdist upload -r pypi

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

dependencies = ['click','requests', 'tabulate', 'whetlab']

setup(
    name='whetlab',
    version='0.2.3.9',
    description='Whetlab client for Python',
        long_description=open('README.md').read(),
    author='Whetlab LLC',
    author_email='info@whetlab.com',
    url='http://www.whetlab.com/',
    license='LICENSE.txt',
    install_requires=dependencies,
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    download_url="https://github.com/whetlab/Whetlab-Python-Client/tarball/0.1",
    keywords=['machine learning', 'optimizing', 'optimization', 'hyperparameters', 'deep learning', 'neural networks'],
    packages=[
        'whetlab',
                'whetlab.server',
                'whetlab.server.api',
                'whetlab.server.error',
                'whetlab.server.http_client'
    ],
    entry_points={
        'console_scripts': [
            'whetlab = whetlab.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: Other/Proprietary License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
