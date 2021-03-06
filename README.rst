**This is a Zabbix 2.4.6 template + discovery & sender script useful to monitor Varnish Cache >= 4.0 instances:**

1. Copy ``zabbix-varnish-cache.py`` to ``/usr/local/bin/``.

2. If using Varnish Cache >= 4.1, add ``zabbix`` user to the ``varnish`` group::

    $ sudo usermod -a --groups varnish zabbix

3. Add the ``varnish.discovery`` user parameter to Zabbix::

    UserParameter=varnish.discovery[*],/usr/local/bin/zabbix-varnish-cache.py -n '$1' discover $2

4. Add a new job to the ``zabbix`` user crontab (beware of the ``-n`` and ``-s`` options). This will submit Varnish Cache metrics through Zabbix Sender::

    * * * * * /usr/local/bin/zabbix-varnish-cache.py send -c /etc/zabbix/zabbix_agentd.conf -s dev > /dev/null 2>&1

5. Import the Varnish Cache template (``template-app-varnish.xml`` file).

6. Add an existing / new host to the ``Varnish Cache servers`` group and link it to the ``Template App Varnish Cache`` template. Beware of the ``{$VARNISH_NAME}`` macro, useful to monitor servers running more than one Varnish Cache instance. Leave it blank if running a single Varnish Cache instance per server.
