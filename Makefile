
run:
	uwsgi -s /tmp/mta-sts.sock --manage-script-name --mount /=check:app --plugins=python3 --chmod-socket=666
