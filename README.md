# 動かし方

以下のコマンドで war を作成して Tomcat 上に配置する。
通常、テストを実行しようが、かなり時間がかかるのでオプションでスキップさせる。

```
maven package -DskipTests=true
```

DB接続情報は src/main/resources/connection.xml に書かれているが、デフォルトだと H2Database を使うので、
適宜情報を修正する。
