from setuptools import find_packages, setup

setup(
    name="nrai-protected-image",
    version="0.1.0",
    description="Prototype container and rights manifest for cooperative protected image handling",
    package_dir={"": "src"},
    packages=find_packages("src"),
    python_requires=">=3.9",
    install_requires=["cryptography>=41"],
    extras_require={"images": ["Pillow>=9"], "test": ["pytest>=7", "Pillow>=9"], "build-desktop": ["pyinstaller>=6", "Pillow>=9"]},
    entry_points={"console_scripts": ["nrai=nrai.cli:main", "nrai-viewer=nrai.viewer:main", "nrai-desktop=nrai.desktop:main"]},
)
