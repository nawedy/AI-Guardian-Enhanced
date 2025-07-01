from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ai-guardian-jupyter",
    version="3.0.0",
    author="OmniPanel AI Team",
    author_email="support@omnipanel.ai",
    description="AI Guardian security scanning extension for Jupyter Notebooks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/omnipanel/ai-guardian",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Framework :: Jupyter",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.7",
    install_requires=[
        "jupyter>=1.0.0",
        "ipython>=7.0.0",
        "ipywidgets>=7.0.0",
        "requests>=2.25.0",
        "websocket-client>=1.0.0",
        "pandas>=1.0.0",
        "matplotlib>=3.0.0",
        "seaborn>=0.11.0",
        "plotly>=5.0.0",
        "nbformat>=5.0.0",
        "traitlets>=5.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
        "colab": [
            "google-colab>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ai-guardian-jupyter=ai_guardian_jupyter.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "ai_guardian_jupyter": [
            "static/*",
            "templates/*",
            "data/*",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/omnipanel/ai-guardian/issues",
        "Source": "https://github.com/omnipanel/ai-guardian",
        "Documentation": "https://ai-guardian.readthedocs.io/",
    },
)

