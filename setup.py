from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cognito-auth-sdk",
    version="1.1.0",
    author="Coastal Seven Team",
    description="AWS Cognito Authentication SDK for FastAPI applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rayudurayapati/coastal_seven_authentication",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "fastapi>=0.104.0",
        "boto3>=1.28.0",
        "PyJWT[crypto]>=2.8.0",
        "cryptography>=41.0.0",
        "requests>=2.31.0",
        "pydantic>=2.0.0",
        "email-validator>=2.0.0",
        "python-dotenv>=1.0.0",
        "uvicorn>=0.24.0"
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
