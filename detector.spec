# -*- mode: python -*-

a = Analysis(['gui.py'],
              pathex=[os.path.dirname(__file__)],
              hookspath=['hooks'])

pyz = PYZ(a.pure)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          Tree('gui', prefix='gui'),
          Tree('rules', prefix='rules'),
          name=os.path.join('dist', 'detekt.exe'),
          debug=False,
          strip=False,
          upx=False,
          console=False,
          icon='detekt.ico')
