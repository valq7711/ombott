from setuptools import setup, find_packages
import ombott

setup(
    name="ombott",
    version=ombott.__version__,
    url="https://github.com/valq7711/ombott",
    license=ombott.__license__,
    author=ombott.__author__,
    author_email="valq7711@gmail.com",
    maintainer=ombott.__author__,
    maintainer_email="valq7711@gmail.com",
    description="One More BOTTle",
    platforms="any",
    keywords='python webapplication',
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires='>=3.7',
    packages=find_packages('.'),
    package_data={'ombott': ['error.html']}
)
