# Online MTA-STS testing tool

This tool verifies whether a give host correctly implements the new
in-development <a href="https://github.com/mrisher/smtp-sts">MTA-STS
standard</a> for downgrade-resistant secure email. It is very new and not very
well tested so don't rely on it's result too much.

Online version: https://aykevl.nl/apps/mta-sts/

License: BSD 2-clause license (see LICENSE.txt).

## Installing on Debian

This guide has been written for Debian buster. It will work on stretch with
minimal modifications (replace python3-flask-limiter with the pip3 package
Flask-Limiter).

 1. Install dependencies:

        $ apt-get install uwsgi uwsgi-plugin-python3 python3-flask python3-flask-limiter python3-dnspython

 2. Create a configuration file for uWSGI
    ([howto](https://uwsgi-docs.readthedocs.io/en/latest/WSGIquickstart.html))
    at `/etc/uwsgi/emperor.ini`:

    ```ini
    [uwsgi]
    emperor = /etc/uwsgi/vassals
    uid = www-data
    gid = www-data
    limit-as = 1024
    logto = /tmp/uwsgi.log
    ```

 3. Create a configuration for this app at `/etc/uwsgi/vassals/mta-sts.ini`
    (create `/etc/uwsgi/vassals` first):

    ```ini
    [uwsgi]
    socket             = /tmp/mta-sts.sock
    manage-script-name = true
    mount              = /=check:app
    plugins            = python3
    chmod-socket       = 666
    pythonpath         = /some/path/mta-sts
    ```

 4. Enable and start uWSGI (check `/tmp/uwsgi.log` for errors):

        $ sytemctl enable emperor.uwsgi.service
        $ sytemctl start emperor.uwsgi.service

 5. Make sure a webserver redirects requests to `/tmp/mta-sts.sock`. For
    example, with nginx:

    ```nginx
    location = /apps/mta-sts/api {
        include uwsgi_params;
        uwsgi_pass unix:/tmp/mta-sts.sock;
    }
    ```

 6. Test the app with a browser.
