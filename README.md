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
