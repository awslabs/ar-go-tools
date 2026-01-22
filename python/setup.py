from setuptools import setup, find_packages

setup(
    name="argot-summary-generator",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        line.strip()
        for line in open("requirements.txt")
        if line.strip() and not line.startswith("#")
    ],
    entry_points={
        "console_scripts": [
            "argot-summarize=summary_generator.generate:main",
        ],
    },
    python_requires=">=3.8",
)
