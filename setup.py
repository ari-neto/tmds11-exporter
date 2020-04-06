#!/usr/bin/env python
# https://docs.python.org/3/distutils/setupscript.html

import sys
import os
from distutils.sysconfig import get_python_lib

from setuptools import setup, find_packages


CURRENT_PYTHON = sys.version_info[:2]
REQUIRED_PYTHON = (3, 6)

#!/usr/bin/env python
# https://docs.python.org/3/distutils/setupscript.html

import sys
import os
from distutils.sysconfig import get_python_lib

from setuptools import setup, find_packages


CURRENT_PYTHON = sys.version_info[:2]
REQUIRED_PYTHON = (2, 7)

# This check and everything above must remain compatible with Python 2.7.
if CURRENT_PYTHON < REQUIRED_PYTHON:
    sys.stderr.write("""
==========================
Unsupported Python version
==========================
This version requires Python {}.{}, but you're trying to
install it on Python {}.{}.
This may be because you are using a version of pip that doesn't
understand the python_requires classifier. Make sure you
have pip >= 9.0 and setuptools >= 24.2, then try again:
    $ python -m pip install --upgrade pip setuptools"
""".format(*(REQUIRED_PYTHON + CURRENT_PYTHON)))
    sys.exit(1)


# Warn if we are installing over top of an existing installation. This can
# cause issues where files that were deleted from a more recent Django are
# still present in site-packages. See #18115.
overlay_warning = False
if "install" in sys.argv:
    lib_paths = [get_python_lib()]
    if lib_paths[0].startswith("/usr/lib/"):
        # We have to try also with an explicit prefix of /usr/local in order to
        # catch Debian's custom user site-packages directory.
        lib_paths.append(get_python_lib(prefix="/usr/local"))
    for lib_path in lib_paths:
        existing_path = os.path.abspath(os.path.join(lib_path, "tmds11-exporter"))
        if os.path.exists(existing_path):
            # We note the need for the warning here, but present it after the
            # command is run, so it's more likely to be seen.
            overlay_warning = True
            break


setup(
    name='tmds11-exporter',
    version='0.0.0',
    author='Ari Neto',
    author_email='ari.oliveira@gmail.com',
    license='apache-2.0',
    description=('A prometheus exporter for deep security'),
    packages=find_packages(include=['app', 'app.*']),
    setup_requires=['pytest-runner', 'flake8', 'autopep8', 'pylint', 'pytest'],
    install_requires=[
        'envparse==0.2.0',
        'prometheus-client==0.7.1'
    ],
    project_urls={
        'Documentation': '-',
        'Source': 'https://gitlab.com/tmselabs/tmds11-exporter',
    },
)







# Warn if we are installing over top of an existing installation. This can
# cause issues where files that were deleted from a more recent Django are
# still present in site-packages. See #18115.
overlay_warning = False
if "install" in sys.argv:
    lib_paths = [get_python_lib()]
    if lib_paths[0].startswith("/usr/lib/"):
        # We have to try also with an explicit prefix of /usr/local in order to
        # catch Debian's custom user site-packages directory.
        lib_paths.append(get_python_lib(prefix="/usr/local"))
    for lib_path in lib_paths:
        existing_path = os.path.abspath(os.path.join(lib_path, "ferryman"))
        if os.path.exists(existing_path):
            # We note the need for the warning here, but present it after the
            # command is run, so it's more likely to be seen.
            overlay_warning = True
            break


setup(
    name='ferryman-slack',
    version='0.0.2',
    author='Ari Neto',
    author_email='ari.oliveira@gmail.com',
    license='apache-2.0',
    description=('A python application to interact with security infos '
                 'at this point, the app is focusing on trend micro apps.'),
    packages=find_packages(include=['app', 'app.*']),
    setup_requires=['pytest-runner', 'flake8', 'autopep8', 'pylint', 'pytest'],
    install_requires=[
        'slackclient==2.3.1',
        'elasticsearch==7.0.4',
        'envparse==0.2.0',
        'apiai==1.2.3',
        'docker-image-py==0.1.10',
        'sentry-sdk==0.13.1',
        'requests==2.22.0'
    ],
    project_urls={
        'Documentation': '-',
        'Source': 'https://github.com/ari-neto/kharon',
    },
)




