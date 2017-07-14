{
  "targets": [
    {
      "target_name": "yara",
      "sources": [
        "src/yara.cc"
      ],
      "cflags_cc!": [
        "-fno-exceptions",
        "-fno-rtti"
      ],
      "include_dirs": [
        "<!(node -e 'require(\"nan\")')",
        "./deps/yara-3.6.0/build/include"
      ],
      "libraries": [
        "-lmagic",
        "../deps/yara-3.6.0/build/lib/libyara.a"
      ],
      "conditions": [
        [
          "OS==\"mac\"",
          {
            "xcode_settings": {
              "GCC_ENABLE_CPP_EXCEPTIONS": "YES"
            }
          }
        ]
      ],
      "actions": [
        {
          "action_name": "build_libyara",
          "inputs": [
            "deps/yara-3.6.0.tar.gz"
          ],
          "outputs": [
            "deps/yara-3.6.0/build"
          ],
          "action": [
            "make",
            "libyara"
          ]
        }
      ]
    }
  ]
}
