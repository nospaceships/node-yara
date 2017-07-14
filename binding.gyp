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
        "./build/yara/include"
      ],
      "libraries": [
        "-lmagic",
        "../build/yara/lib/libyara.a"
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
            "deps"
          ],
          "outputs": [
            "build/yara"
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
