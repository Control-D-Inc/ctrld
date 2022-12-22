# Control D config

`ctrld` can build a Control D config and run with the specific resolver data.

For example:

```shell
ctrld run --cd p2
```

Above command will fetch the `p2` resolver data from Control D API and use that data for running `ctrld`:

 - The resolver `doh` endpoint will be used as the primary upstream.
 - The resolver `exclude` list will be used to create a rule policy which will steer them to the default OS resolver.
```
