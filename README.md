# 動かし方

以下のコマンドで war を作成して Tomcat 上に配置する。
通常、テストを実行しようが、かなり時間がかかるのでオプションでスキップさせる。

```
maven package -DskipTests=true
```

DB接続情報は src/main/resources/connection.xml に書かれているが、デフォルトだと H2Database を使うので、
適宜情報を修正する。

# OAuth 用情報の設定方法

クライアントID, クライアントシークレット、リダイレクトURLを環境変数から取得する。

## Windows

「システム環境変数」として設定する。

## Linux

コンテナ上での稼働を想定しているので、Docker 経由で環境変数をコンテナに渡す。
例えば、Docker Compose を使っている場合、app.env というファイルを作り、それに記述する。

```
...
app:
  image: koda/docker-knowledge
  env_file:
    - /.../app.env
...
```