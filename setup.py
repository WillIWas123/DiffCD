from setuptools import setup, find_packages

with open("README.md", "r") as f:
    LONG_DESCRIPTION = f.read()

VERSION = "1.0.7"
DESCRIPTION = "Content Discovery tool using response diffing for finding more interesting/hidden content on web applications."

setup(
    name="DiffCD",
    version=VERSION,
    author="William Kristoffersen",
    author_email="william.kristof@gmail.com",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=["requests","httpdiff","httpinsert"],
    classifiers=[],
    scripts=["diffcd/diffcd"]

)
