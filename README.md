I am currently testing afl++ unicorn_mode.

a.out is the target (example.c).

`python3 harness.py img_meta_4x4.img` works, but

`afl-fuzz -U -m none -i IN -i OUT -- python3 harness.py @@` crashes.
