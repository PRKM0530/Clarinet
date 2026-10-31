"""
clarinet/jobs
Background jobs, one module per area of ownership.

Every module here may define register(scheduler), which receives the
APScheduler instance and adds its own jobs. scheduler.py discovers the modules
automatically, so adding a job never means editing a shared file.
"""
