# mysql-audit-proxy
Proxy for mysql audit recording


Download
-------------

[release page](https://github.com/masahide/mysql-audit-proxy/releases)

Usage:
---------

```bash
  mysql-audit-proxy [flags]

Flags:
      --buf string        buffer size (default "32mb")
      --q int             max log buffer queues (default 200)
      --flush duration    time to flush buffer (default 1s)
      --listen string     Listen address [ip or hostname or socketFileName]  (default "localhost:3330")
      --net string        Listen net ['tcp' or 'unix']  (default "tcp")
      --log string        logfile path (default "mysql-audit.%Y%m%d%H.log")
      --rotate duration   logfile rotatetime (default 1h0m0s)
      --logGzip           Gzip compress log files
  -h, --help              help for mysql-audit-proxy
```


test
---------

```bash
# start mysql 5.7
docker run --rm --name demo_mysql -e MYSQL_ROOT_PASSWORD=secret -d mysql:5.7

# connect
MYSQL_PWD=secret mysql -h 127.0.0.1 -uroot

# Execute sql
MYSQL_PWD=secret mysql -h 127.0.0.1 -uroot -e "select CHAR_LENGTH('hnogedff') as len"

# run mysql-audit-proxy
./mysql-audit-proxy --listen :3330 --log tmp/%Y%m%d%H%M.log --logGzip --rotate 1m

# Execute SQL through proxy
mysql -h 127.0.0.1 -P 3330 -u 'root:secret@127.0.0.1:3306' -e "select CHAR_LENGTH('hnogedff') as len"
```
