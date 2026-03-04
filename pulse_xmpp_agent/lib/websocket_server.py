#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import asyncio
import logging
import aiofiles
import argparse
import websockets

logger = logging.getLogger()
log_tailers = {}

async def read_file_content(filepath, mode):
    async with aiofiles.open(filepath, 'r') as f:
        if mode == "complete":
            return await f.read()
        elif mode.startswith("tail"):
            try:
                count = int(mode[4:])
            except ValueError:
                count = 10
            lines = await f.readlines()
            return "".join(lines[-count:])
        else:
            return ""

class LogTailer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.subscribers = set()

    def add_subscriber(self, websocket):
        self.subscribers.add(websocket)

    def remove_subscriber(self, websocket):
        self.subscribers.discard(websocket)

    async def tail_loop(self):
        async with aiofiles.open(self.filepath, 'r') as f:
            await f.seek(0, 2)
            while True:
                line = await f.readline()
                if not line:
                    await asyncio.sleep(0.1)
                    continue
                message = json.dumps({
                    "type": "log",
                    "data": line.rstrip()
                })
                for subscriber in list(self.subscribers):
                    try:
                        await subscriber.send(message)
                    except Exception as e:
                        logger.error(f"Unexpected error:", {e})
                        self.remove_subscriber(subscriber)

class WebSocketHandler:
    def __init__(self, websocket):
        self.websocket = websocket

    async def handle(self):
        try:
            async for message in self.websocket:
                await self.process_message(message)
        except websockets.exceptions.ConnectionClosed as e:
            logger.error(f"Closed connection: {e.code} - {e.reason}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        finally:
            for tailer in log_tailers.values():
                tailer.remove_subscriber(self.websocket)
            try:
                await self.websocket.close()
            except Exception as e:
                logger.error(f"Error by closing Websocket: {e}")

    async def process_message(self, message):
        try:
            data = json.loads(message)
        except Exception:
            data = {"command": message.lower()}
        command = data.get("command", "").lower()

        if command == "subscribe":
            group = data.get("group", "").lower()
            file_choice = data.get("file", "").lower()
            mode = data.get("mode", "complete").lower()
            tailer = None

            if group and group in log_tailers:
                tailer = log_tailers[group].get(file_choice)

            if tailer:
                if mode == "complete":
                    content = await read_file_content(tailer.filepath, "complete")
                    await self.websocket.send(json.dumps({"type": "log", "data": content}))
                elif mode.startswith("tail"):
                    content = await read_file_content(tailer.filepath, mode)
                    await self.websocket.send(json.dumps({"type": "log", "data": content}))
                    tailer.add_subscriber(self.websocket)
                elif mode.startswith("partial"):
                    tail_mode = "tail" + mode[7:]
                    content = await read_file_content(tailer.filepath, tail_mode)
                    await self.websocket.send(json.dumps({"type": "log", "data": content}))
                else:
                    await self.websocket.send(json.dumps({
                        "type": "message",
                        "data": f"Unknown mode: {mode}"
                    }))
            else:
                await self.websocket.send(json.dumps({
                    "type": "message",
                    "data": f"Unknown log file: {group}/{file_choice}"
                }))
        elif command == "unsubscribe":
            for group in log_tailers.values():
                if isinstance(group, dict):
                    for tailer in group.values():
                        tailer.remove_subscriber(self.websocket)
                else:
                    group.remove_subscriber(self.websocket)
        elif command == "list":
            # Create an answer containing the list of files followed
            files_list = {}
            for group, logs in log_tailers.items():
                if isinstance(logs, dict):
                    files_list[group] = {key: tailer.filepath for key, tailer in logs.items()}
                else:
                    files_list[group] = logs.filepath
            await self.websocket.send(json.dumps({
                "type": "list",
                "data": files_list
            }))
        elif command == "message":
            await self.websocket.send(json.dumps({
                "type": "message",
                "data": f"Message received: {data.get('data', '')}"
            }))
        else:
            await self.websocket.send(json.dumps({
                "type": "message",
                "data": f"Unknown command: {command}"
            }))

async def handler(websocket, path="/"):
    ws_handler = WebSocketHandler(websocket)
    await ws_handler.handle()

async def list_logs():
    uri = "ws://127.0.0.1:5555"
    try:
        async with websockets.connect(uri) as websocket:
            await websocket.send(json.dumps({"command": "list"}))
            response = await websocket.recv()
            data = json.loads(response)
            if data.get("type") == "list":
                print("Files followed :")
                for group, logs in data["data"].items():
                    if isinstance(logs, dict):
                        for key, filepath in logs.items():
                            print(f"{group}/{key} : {filepath}")
                    else:
                        print(f"{group} : {logs}")
            else:
                print("Unexpected response :", data)
    except Exception as e:
        print("Error when connecting to the server :", e)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Websocket server with JSON configuration for Tailers log"
    )
    parser.add_argument(
        "--log_path",
        type=str,
        required=None,
        help="JSON chain of logs, for example: '{\"access\": \"/var/log/apache2/access.log\", \"error\": \"/var/log/apache2/error.log\"}'"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List the files that are being monitored and exit."
    )
    return parser.parse_args()

def load_log_tailers_from_args(json_config):
    """
    Decods the nested JSON configuration and creates the Tailers logs.
    The configuration must be of the type:
      {
        "apache2": {"access": "/var/log/apache2/access.log", "error": "/var/log/apache2/error.log"},
        "ejabberd": {"ejabberd": "/var/log/ejabberd/ejabberd.log", "error": "/var/log/ejabberd/error.log"},
        ...
      }
    """
    try:
        config = json.loads(json_config)
    except Exception as e:
        logger.error("Error when decoding the JSON configuration:", e)
        config = {}
    global log_tailers
    log_tailers = {}
    for group, logs in config.items():
        if isinstance(logs, dict):
            group_key = group.lower()
            log_tailers[group_key] = {}
            for key, filepath in logs.items():
                file_key = key.lower()
                log_tailers[group_key][file_key] = LogTailer(filepath)
                print(f"Logtailer added for {group_key}/{file_key} -> {filepath}")
        else:
            log_tailers[group.lower()] = LogTailer(logs)
            print(f"Logtailer added for {group.lower()} -> {logs}")

async def main():
    args = parse_args()
    if args.list:
        await list_logs()
        return

    load_log_tailers_from_args(args.log_path)

    for group in log_tailers.values():
        if isinstance(group, dict):
            for tailer in group.values():
                asyncio.create_task(tailer.tail_loop())
        else:
            asyncio.create_task(group.tail_loop())

    # Start the WebSocket server on all interfaces, Port 5555
    server = await websockets.serve(handler, "0.0.0.0", 5555)
    print("Websocket server launched on ws://127.0.0.1:5555")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())