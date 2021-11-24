{
  "includes": [ "deps/common.gypi" ],
  'targets': [
    {
      'target_name': 'node_cryptokit',
      'sources': [ 'src/addon.cc',
                    'src/ctk_util.cc'],

      'include_dirs': ["<!@(node -p \"require('node-addon-api').include\")",
      'deps/src'],
      "conditions": [
        ['OS == "win"', {
          "libraries": [
            '-lCTK.lib',
            ]
        },
        'OS == "mac"', {
          "libraries": [
            '<(PRODUCT_DIR)/CTK.a',
            ]
        }]
      ],
       
      'dependencies': ["<!(node -p \"require('node-addon-api').gyp\")",
              "deps/CTK.gyp:CTK"
      ],
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions' ],
      'xcode_settings': {
        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
        'CLANG_CXX_LIBRARY': 'libc++',
        'MACOSX_DEPLOYMENT_TARGET': '10.7'
      },
      'msvs_settings': {
        'VCCLCompilerTool': { 'ExceptionHandling': 1 },
        "VCLinkerTool": {
                "AdditionalLibraryDirectories": [
                  "<(SHARED_INTERMEDIATE_DIR)/../../"
                ]
              }
      }
    }
  ]
}