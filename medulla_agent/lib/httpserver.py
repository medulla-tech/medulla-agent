#!/usr/bin/python3
# coding: utf-8
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Run a http web server
"""

import os
from datetime import datetime
import cherrypy


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

        size = "{:.2f}".format(size_bite / (refactor**count))
        return f"{size} {units[count]}"

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
        final_list = []
        # Test if the path exists
        if os.path.exists(str_path):
            # Get all elements
            raw_list = os.listdir(str_path)

            # Then we need to filter the raw_list
            for element in raw_list:
                abspath = os.path.join(str_path, element)
                if element.lower().endswith(tuple(list_ext)) or "*" in list_ext:
                    # we want the creation date
                    timestamp = os.path.getmtime(abspath)
                    element_type = "d" if os.path.isdir(abspath) else "f"
                    # we want the file size
                    size = os.path.getsize(abspath)
                    size = Controller.transform_size(size)
                    final_list.append(
                        (
                            element,
                            datetime.fromtimestamp(timestamp).strftime(
                                Controller.config.date_format
                            ),
                            size,
                            element_type,
                            abspath,
                        )
                    )

        else:
            print(f"{str_path} doesn't exist")
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

        for count, name in enumerate(Controller.config.names):
            jstablenames.append(f'#table-{name.replace(" ", "")}')
            list_elements = Controller.get_list_from_path(
                Controller.config.paths[count], Controller.config.extensions[count]
            )
            tabs += f"""<li><a href="#tabs-{name.replace(" ", "")}">{name}</a></li>"""
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
                <tbody>""".format(
                name.replace(" ", ""),
                name,
                Controller.config.paths[count],
                name.replace(" ", ""),
            )

            for element, date, size, type, path in list_elements:
                html += (
                    """<tr class="anchor" id="{}">
                <td>
                    <a href="#{}" onclick="show_dialog('{}', '{}', this, {}, {})">{}</a>
                    <div class="dialog resizable" style="display:none">
                        <p></p>
                    </div>
                </td>
                <td>{}</td>
                <td>{}</td>
                <td><a href="{}/{}" download>Download</a></td>
            </tr>""".format(
                        element,
                        element,
                        name,
                        element,
                        Controller.config.fv_minwidth,
                        Controller.config.fv_maxwidth,
                        element,
                        date,
                        size,
                        name,
                        element,
                    )
                    if type == "f"
                    else """<tr class="anchor" id="{}">
                <td>{}</td>
                <td></td>
                <td></td>
                <td></td>
            </tr>""".format(
                        element, element
                    )
                )
            html += "</tbody></table></div>"
        tabs += "</ul>"

        return """<!doctype html>
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
                .resizable { min-width: %spx; max-width:%spx; padding: 0.5em; }
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
        </html>""" % (
            ",".join(jstablenames),
            Controller.config.fv_minwidth,
            Controller.config.fv_maxwidth,
            tabs,
            html,
        )
