# Django introduction

```bash
python3 -m virtualenv {env_name}            # create new env
source {env_name}/bin/activate              # activate your env
pip3 install Django==2.2.12                 # install Django
django-admin startproject {project_name}    # start project
python3 manage.py migrate                   # configure new files
```

_`manage.py` is a command-line utility that lets you interact with your Django project in various ways. It is especially handy in creating web-apps, managing databases, and most importantly running the server._


```bash
python3 manage.py startapp {app_name}
```