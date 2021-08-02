from setuptools import setup

import ombott

setup(
    name="ombott-Val",
    version=ombott.__version__,
    url="https://github.com/valq7711/ombott",
    license=ombott.__license__,
    author=ombott.__author__,
    author_email="valq7711@gmail.com",
    maintainer=ombott.__author__,
    maintainer_email="valq7711@gmail.com",
    description="One More BOTTle",
    packages=['ombott'],
    platforms="any",
    scripts=['ombott.py'],
    keywords='python webapplication',
    classifiers=[
        "Development Status :: 1 - Planning",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires='>=3.8',
)
