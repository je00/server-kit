# 本地密钥生成器构建

发布包使用固定文件顺序、固定时间和无压缩存储，便于复核源码与 ZIP 的 SHA-256。

```bash
python3 tools/build_browser_extension.py build \
  --output dist/server-kit-local-key-generator-0.4.1.zip \
  --manifest-output browser_extension/release-manifest.json
python3 tools/build_browser_extension.py verify \
  --manifest browser_extension/release-manifest.json
```

源码发生变化时必须提升 `manifest.json` 版本并重新生成发布清单。扩展没有联网权限，也没有配对或签名功能；用户可以直接加载已解压目录，或自行分发构建出的 ZIP。
