{
  'includes': [ 'common.gypi' ],

  'target_defaults': {
    'default_configuration': 'Release',
    'cflags':[
      '-std=c99'
    ],
    'configurations': {
      'Debug': {
        'defines': [ 'DEBUG', '_DEBUG' ],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'RuntimeLibrary': 1, # static debug
          },
        },
      },
      'Release': {
        'defines': [ 'NDEBUG' ],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'RuntimeLibrary': 0, # static release
          },
        },
      }
    },
    'msvs_settings': {
      'VCCLCompilerTool': {
      },
      'VCLibrarianTool': {
      },
      'VCLinkerTool': {
        'GenerateDebugInformation': 'false',
      },
    },
    'conditions': [
      ['OS == "win"', {
        'defines': [
          'WIN32'
        ],
        'conditions': [
          ['target_arch == "ia32"', {
            'variables': {
              'openssl_lib%': 'x86',
            }
          }, 'target_arch == "arm64"', {
            'variables': {
              'openssl_lib%': 'x64',
            }
          }, {
            'variables': {
              'openssl_lib%': 'x64',
            }
          }]
        ],
        'link_settings': {
          'libraries': [
            '-llibcrypto.lib',
            '-llibssl.lib',
            # The two libs below are needed for the Electron build to succeed
            '-lws2_32.lib',
            '-lcrypt32.lib'
          ],
          'library_dirs': [
            'OpenSSL/Windows/lib/<(openssl_lib)'
          ]
        }
      },
      'OS == "mac"', {
        'link_settings': {
          'libraries': [
            # This statically links libcrypto, whereas -lcrypto would dynamically link it
            '<(PRODUCT_DIR)/../../deps/OpenSSL/Mac/lib/libcrypto.a'
          ]
        }
      }
      ]
    ],
  },

  'targets': [ 
    {
      'target_name': 'CTK',
      'type': 'static_library',
      "conditions": [
        ['OS == "win"', {
          'include_dirs': [
            'OpenSSL/Windows/include',
          ]
        },
        'OS == "mac"', {
          'include_dirs': [
            'OpenSSL/Mac/include',
          ]
        }]
      ],

      'sources': [
        'src/Base64.cc',
        'src/cJSON.c',
        'src/cJSON_Utils.c',
        'src/CryptoKit.cc',
        'src/CryptoKitEngine.cc'
      ],
      'cflags_cc': [
          '-Wno-unused-value'
      ],

    }
  ]
}
