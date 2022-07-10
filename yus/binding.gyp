{
  'variables': {
    'module_name': 'yus',
    'module_path': './build'
  },
  'targets': [
    {
      'target_name': '<(module_name)',
      'defines': [
        'NAPI_DISABLE_CPP_EXCEPTIONS'
      ],
      'include_dirs': [
        '<!(node -p "require(\'node-addon-api\').include_dir")',
        '<(module_root_dir)/include/'
      ],
      'cflags!': [
        '-fno-exceptions'
      ],
      'cflags_cc!': [
        '-fno-exceptions'
      ],
      'msvs_guid': 'FAE04EC0-301F-11D3-BF4B-00C04F79EFBC',
      'msvs_settings': {
        'VCCLCompilerTool': {
          'ExceptionHandling': 1
        },
      },
      'conditions': [
        [
          'OS == "win"',
          {
            'defines': [
              'WIN32',
              'NDEBUG'
            ],
            'sources': [
              'src/main_win.cpp',
            ],
            'conditions': [
              [
                'target_arch == "x64"',
                {
                  'libraries': [
                    '<(module_root_dir)/lib/npcap/x64/Packet.lib',
                    '<(module_root_dir)/lib/npcap/x64/wpcap.lib'
                  ]
                }
              ]
            ]
          }
        ],
        [
          'OS != "win"',
          {
            'sources': [
              'src/main_linux.cpp',
            ]
          }
        ]
      ]
    },
    {
      'target_name': 'action_after_build',
      'type': 'none',
      'dependencies': [
        '<(module_name)'
      ],
      'copies': [
        {
          'files': [
            '<(PRODUCT_DIR)/<(module_name).node',
          ],
          'destination': '<(module_path)'
        }
      ]
    }
  ]
}
