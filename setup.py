from setuptools import setup, find_packages

setup(
    name="miraicfg",
    version="0.1.0",
    description="Mirai configuration extraction utility",
    url="https://github.com/FernandoDoming/identikit",
    author="Fernando Domínguez",
    author_email="fernando.dom.del@gmail.com",
    license="GNU GPL v3",
    packages=find_packages(),
    install_requires=[
        "r2pipe>=1.6.3",
    ],

    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8"
    ],

    entry_points = {
        "console_scripts": ["miraicfg=miraicfg.dump:main"]
    },
    include_package_data=True,
)
