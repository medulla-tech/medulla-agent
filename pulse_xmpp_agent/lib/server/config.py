#!/usr/bin/env python
# coding: utf-8

"""General http server conf reader"""

import os
from configparser import ConfigParser


class Config(ConfigParser):
    """Config http server class"""
    def __init__(self, file=""):
        try:
            super().__init__()
        except:
            super(Config, self).__init__()
        if file != "":
            if os.path.exists(file):
                self.read(file)

        # Get fileviewer from conf
        self.paths = []
        self.names = []
        self.extensions = []
        self.date_format = '%Y-%m-%d %H:%M:%S'
        self.fadein_speed = 500
        self.fadeout_speed = 500

        if self.has_option('fileviewer', 'sources'):
            self.paths = self.get('fileviewer', 'sources').split(';')

        # The size_paths drive the final size of paths, names and extensions parameters
        size_paths = len(self.paths)

        if self.has_option('fileviewer', 'names'):
            # Get names from ini file
            self.names = self.get('fileviewer', 'names').split(';')

        # If some names are missing, complete display names associated to each paths
        count = 0
        while count < size_paths:
            try:
                self.names[count]
            except IndexError:
                # The displayed names are in lowercase
                self.names.append(os.path.basename(self.paths[count]).lower())
            finally:
                count += 1

        # Get available extensions
        if self.has_option('fileviewer', 'extensions'):
            self.extensions = self.get('fileviewer', 'extensions').split(';')

        # If some extensions group are missing, complete the list for each paths
        count = 0
        while count < size_paths:
            try:
                self.extensions[count]
            except IndexError:
                self.extensions.append([])
            finally:
                count += 1

        count = 0
        while count < size_paths:
            if type(self.extensions[count]) is list:
                self.extensions[count] = self.extensions[count]
            else:
                self.extensions[count] = self.extensions[count].split(',')
            count += 1

        if self.has_option('fileviewer', 'date_format'):
            self.date_format = self.get('fileviewer', 'date_format')

        if self.has_option('fileviewer', 'fadein_speed'):
            try:
                self.fadein_speed = self.getint('fileviewer', 'fadein_speed')
            except:
                self.fadein_speed = 500

        if self.has_option('fileviewer', 'fadeout_speed'):
            try:
                self.fadein_speed = self.getint('fileviewer', 'fadeout_speed')
            except:
                self.fadeout_speed = 500
