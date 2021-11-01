# 動かし方

以下のコマンドで war を作成して Tomcat 上に配置する。
通常、テストを実行しようが、かなり時間がかかるのでオプションでスキップさせる。

```
maven package -DskipTests=true
```

DB接続情報は src/main/resources/connection.xml に書かれているが、デフォルトだと H2Database を使うので、
適宜情報を修正する。

# OAuth 用情報の設定方法

環境変数でクライアントID, クライアントシークレット、リダイレクトURLを設定することを想定している。

## Windows

「システム環境変数」として設定する。

## Linux

app.env というファイルを作り、それに記述する。