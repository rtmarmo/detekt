Detekt
======

Detekt is a Python tool that relies on Yara to scan the memory of a running Windows system (currently supporting Windows XP to Windows 8.1 both 32 and 64bit).

Detekt tries to detect the presence of pre-defined patterns that have been identified through the course of our research to be unique identifiers that indicate the presence of a given malware running on the computer. Currently it is provided with patterns for:

- DarkComet RAT
- XtremeRAT
- BlackShades RAT
- njRAT
- FinFisher FinSpy
- HackingTeam RCS
- ShadowTech RAT
- Gh0st RAT

Beware that it is possible that Detekt may not successfully detect the most recent versions of those malware families. Indeed, some of them will likely be updated in response to this release in order to remove or change the patterns that we identified. In addition, there may be existing versions of malware, from these families or from other providers, which are not detected by this tool. If Detekt does not find anything, this unfortunately cannot be considered a clean bill of health.

If you encounter samples of such families that are not successfully detected, please open a ticket. In addition, please let us know if you find instances of false positives.

Requirements
------------

When compiling the tool on Windows systems, you'll have to install some requirements first, including:

- Python 2.7
- Yara 3.x
- Psutil
- PyQt4
- PyWin32

Make sure that you install the latest available version of these libraries, for the right architecture and the right version of Python.
You can download latest version of Yara installers for Windows here https://drive.google.com/folderview?id=0BznOMqZ9f3VUek8yN3VvSGdhRFU&usp=sharing#list
In order for Yara to work correctly you will also need to install Visual C++ 2010 Runtime.

Cloning and compiling
---------------------

Once all requirements are installed on your Windows environment, make sure you clone the full repository and submodules with:

    $ git clone --recursive https://github.com/botherder/detekt.git

This will clone also the PyInstaller trunk. Copy the whole directory in your Windows environment and launch the ``make.bat`` script, which should successfully generate the final executable.

Known Issues
------------

Some Yara signatures need to be improved, as currently some of them are not able to detect all existing variants of the respective malware families.

Signature
---------

The distributed binary is signed with my personal PGP key, the public key is available at https://nex.sx/nex.asc
