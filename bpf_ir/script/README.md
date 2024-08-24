## building with clang

When use clang, some flags should be disabled:

```
'-fconserve-stack',
'-fno-var-tracking-assignments',
'-femit-struct-debug-baseonly',
'-fconserve-stack',
'-fno-code-hoisting',
'-femit-struct-debug-detailed=any',
```