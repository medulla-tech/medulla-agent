#!/usr/bin/env python
# coding: utf-8

"""Run a http web server"""

import os
import sys
from datetime import datetime
import cherrypy

# Get the project config
from config import Config


class Controller:
    """Controller for the cherrypy http server"""
    config = None

    @staticmethod
    def transform_size(size_bite):
        """Transform the size in bites to its multiple
        @param:
            - int size_bite : the file size in bites
        @returns:
            - str containing the size with its unit (b, Kb, Mb, Gb, Tb)
        """
        refactor = 1000
        units = ["b", "Kb", "Mb", "Gb", "Tb"]

        count = 0
        while size_bite / (refactor**count) > 1000:
            count += 1

        size = "{:.2f}".format(size_bite/(refactor**count))
        return "%s %s" % (size, units[count])

    @staticmethod
    def get_list_from_path(str_path, list_ext=[]):
        """Test the given path and returns the files inside it. If a list of
        extensions is specified, returns only filenames which have the
        specified extension.

        @params:
            - str str_path : the root dir we want the subfiles
            - list list_ext : list of allowed extensions

        @returns:
            A list of tuples (filename, date, size)
        """
        # ext = ['.jpg', '.bmp', '.jpeg', '.png', '.gif']
        final_list = []
        # Test if the path exists
        if os.path.exists(str_path):

            # Get all elements
            raw_list = os.listdir(str_path)

            # Then we need to filter the raw_list
            for element in raw_list:
                abspath = os.path.join(str_path, element)
                if element.lower().endswith(tuple(list_ext)) or '*' in list_ext:
                    # we want the creation date
                    timestamp = os.path.getmtime(abspath)
                    element_type = 'd' if os.path.isdir(abspath) else 'f'
                    # we want the file size
                    size = os.path.getsize(abspath)
                    size = Controller.transform_size(size)
                    print(timestamp)
                    print(datetime.fromtimestamp(timestamp))
                    print(datetime.fromtimestamp(timestamp).strftime("%d-%m-%Y %H:%M:%S"))
                    print(datetime.fromtimestamp(timestamp).strftime(Controller.config.date_format))
                    final_list.append((element,
                        datetime.fromtimestamp(timestamp).strftime(Controller.config.date_format),
                        size,
                        element_type,
                        abspath))

        else:
            print("{} doesn't exist".format(str_path))
        return final_list

    @cherrypy.expose
    def index(self):
        """Index View, no get parameters are send. Generates a view of files
        Call: http://host:port/
        """

        """Index View, no get parameters are send. Generates a view of files
        Call: http://host:port/
        """
        html = ""
        tabs = "<ul>"
        jstablenames = []

        count = 0
        for name in Controller.config.names:
            jstablenames.append("#table-{}".format(name.replace(' ', '')))
            list_elements = Controller.get_list_from_path(Controller.config.paths[count], Controller.config.extensions[count])
            tabs += """<li><a href="#tabs-%s">%s</a></li>""" % (name.replace(' ', ''), name)
            html += """<div id="tabs-{}">
            <h1>{} in {}</h1>

            <table id="table-{}" class="display">
                <thead>
                    <tr>
                        <th>File Name</th>
                        <th>Date</th>
                        <th>Size</th>
                        <th>Download</th>
                    </tr>
                </thead>
                <tbody>""".format(name.replace(' ', ''), name, Controller.config.paths[count], name.replace(' ', ''))

            for element, date, size, type, path in list_elements:
                if type == 'f':
                    html += """<tr class="anchor" id="{}">
                <td>
                    <a href="#{}" onclick="show_dialog('{}', '{}', this)">{}</a>
                    <div class="dialog resizable" style="display:none">
                        <p></p>
                    </div>
                </td>
                <td>{}</td>
                <td>{}</td>
                <td><a href="{}/{}" download>Download</a></td>
            </tr>""".format(element, element, name, element, element, date, size, name, element)
                else:
                    html += """<tr class="anchor" id="{}">
                <td>{}</td>
                <td></td>
                <td></td>
                <td></td>
            </tr>""".format(element, element)
            html += '</tbody></table></div>'
            count += 1
        tabs += '</ul>'

        template = """<!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>jQuery UI Tabs - Default functionality</title>
            <link rel="stylesheet" href="css/jquery-ui.css">
            <link rel="stylesheet" href="css/style.css">
            <link rel="stylesheet" href="css/datatables.css">


            <script src="js/jquery.js"></script>
            <script src="js/jquery-ui.js"></script>
            <script>
                // jstablenames contains tabs names. This is necessary to send datas from python to js external script
                jstablenames = '%s'

            </script>
            <script src="js/datatables.js"></script>

            <script src='js/script.js'></script>

        </head>
            <body>

                <style>
                .resizable { max-width:600px; padding: 0.5em; }
                .anchor a:focus{
                    background-color:rgb(210,210,210);
                }
                </style>
                <div id="dialog" class="resizable" title="Preview" style="display:none">
                    <object></object>
                </div>

                <div id="tabs">
                    %s
                    %s
                </div>
            </body>
        </html>""" % (','.join(jstablenames), tabs, html)
        return template

"""
#
# Uncomment all the following section to use the the server in standalone mode
#

def get_agent_conf_dir():
    if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
        return os.path.join('/', 'etc', 'pulse-xmpp-agent', 'agentconf.ini')
    elif sys.platform.startswith('win'):
        return os.path.join('C:/', 'Program Files', 'Pulse', 'etc', 'agentconf.ini')
    else:
        return False


if __name__ == "__main__":
    port = 52044
    root_path = os.path.abspath(os.getcwd())
    agent_dir = get_agent_conf_dir()

    if get_agent_conf_dir() != False and os.path.isfile(get_agent_conf_dir()):
        config_path = get_agent_conf_dir()
    else:
        config_path = os.path.join(root_path, 'config.ini')

    pid = os.getpid()
    with open(os.path.join(root_path, "http.PID"), "w") as pid_file:
        pid_file.write("%s"%pid)
        pid_file.close()

    # Get general config
    print('Using config file : %s'%config_path)

    Controller.config = config = Config(config_path)

    server_conf = {

        # Root access
        'global':{
            'server.socket_host': '0.0.0.0',
            'server.socket_port': port,
        },
        '/': {
            #'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.abspath(os.getcwd())
        },
        # Sharing css ...
        '/css': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.path.abspath(os.getcwd()), 'public', 'css')
        },
        # Sharing js ...
        '/js': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.path.abspath(os.getcwd()), 'public', 'js'),
        },
        # Sharing images ...
        '/images': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.path.abspath(os.getcwd()), 'public', 'images')
        },
        # Alias to images for datatables js lib
        '/DataTables-1.10.21/images': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.path.abspath(os.getcwd()), 'public', 'images'),
        },
        # Sharing fonts
        '/fonts': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.path.abspath(os.getcwd()), 'public', 'fonts'),
        },
    }
    count = 0
    for path in config.paths:
        name = config.names[count]
        # Here we know the name and the path, we can add the access for each folders
        server_conf['/%s' % str(name)] = {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': str(path)
        }
        count += 1

    # cherrypy.quickstart(Controller(), '/', server_conf)

    # From : http://www.zacwitte.com/running-cherrypy-on-multiple-ports-example
    cherrypy.tree.mount(Controller(), '/', server_conf)
    cherrypy.server.unsubscribe()

    server1 = cherrypy._cpserver.Server()
    server1.socket_port=port
    server1._socket_host='0.0.0.0'
    # server1.thread_pool=30
    # server1.ssl_module = 'pyopenssl'
    # server1.ssl_certificate = '/home/ubuntu/my_cert.crt'
    # server1.ssl_private_key = '/home/ubuntu/my_cert.key'
    # server1.ssl_certificate_chain = '/home/ubuntu/gd_bundle.crt'
    server1.subscribe()

    cherrypy.engine.start()
    cherrypy.engine.block()"""
