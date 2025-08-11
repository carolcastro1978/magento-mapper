from cx_Freeze import setup, Executable

setup(
    name="Event/Plugin/Preference Mapper",
    version="1.0",
    description="Events, plugins and preferences mapper",
    executables=[Executable("main.py")]
)