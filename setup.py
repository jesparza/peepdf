from setuptools import find_packages, setup

setup(
    name = "peepdf",
    version = "0.3-r235",
    author = "Jose Miguel Esparza",
    license = "GNU GPLv3",
    url = "http://eternal-todo.com",
    install_requires = [ "jsbeautifier==1.6.2", "colorama" ],
    packages = find_packages(),
)
