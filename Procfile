web: gunicorn --worker-class eventlet -w 1 wsgi:application
release: flask db upgrade
