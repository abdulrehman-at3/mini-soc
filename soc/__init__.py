"""
soc — the framework-agnostic core of Mini-SOC.

Nothing in this package imports Flask. It can be driven equally from
`cli.py` or from `dashboard/app.py`. Keeping the detection/storage logic
independent of the web layer makes it possible to unit test it in
isolation and to reuse it from a scheduled job (e.g. cron) with no
dashboard running at all.
"""
