from setuptools import setup

setup(
    name="peepdf",
    version="0.4.0",
    author="Jose Miguel Esparza",
    license="GNU GPLv3",
    url="http://eternal-todo.com",
    install_requires=[
        "jsbeautifier",
        "colorama",
        "Pillow",
        "future",
        "pythonaes==1.0",
    ],
    entry_points={
        "console_scripts": [
            "peepdf = peepdf.main:main",
        ],
    },
    packages=[
        "peepdf",
    ],
)
