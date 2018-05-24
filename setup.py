from setuptools import setup

setup(name='Multilevel MDA-Lite Paris Traceroute',
      version='0.1',
      description='Costless version of MDA + Router level view of traceroute',
      url='https://gitlab.planet-lab.eu/',
      author='Kevin Vermeulen,',
      author_email='kevinmylinh.vermeulen@gmail.com',
      license='MIT',
      packages=['Alias', 'Graph', 'Maths', 'Packets'],
      install_requires=[
          'scapy',
      ],
      zip_safe=False)