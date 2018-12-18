from setuptools import setup, find_packages

setup(name='Multilevel MDA-Lite Paris Traceroute',
      version='0.1',
      description='Costless version of MDA + Router level view of traceroute',
      url='https://gitlab.planet-lab.eu/',
      author='Kevin Vermeulen,',
      author_email='kevinmylinh.vermeulen@gmail.com',
      license='MIT',
      entry_points={
          "console_scripts": [
              'mda-lite = Network.MdaLite:main',
              'ripe-mda = Network.RIPE_MDA:main',
            ], 
      },
      packages=find_packages(),
      install_requires=[
          'scapy', 'netifaces', 'graph-tool'
      ],
      zip_safe=False)
