from setuptools import setup

setup(
    name="peepdf",
    version="0.3.8",
    author="Jose Miguel Esparza",
    license="GNU GPLv3",
    url="http://eternal-todo.com",
    description= ("The original peepdf, packaged in a setup"),
    install_requires=[
        "jsbeautifier",
        "colorama",
        "Pillow",
        "pythonaes",
        "pylibemu",
        "lxml",
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
