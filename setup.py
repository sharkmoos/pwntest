from setuptools import setup, find_packages

setup(name='pwntest',
      version='0.1',
      url='https://github.com/sharkmoos/pwntest',
      license='MIT',
      author='Ben Roxbee Cox',
      author_email='muddy117@gmail.com',
      description='Framework CTF challenge unit tests',
      packages=find_packages(exclude=['tests']),
      long_description=open('README.md').read(),
      zip_safe=False

      )
