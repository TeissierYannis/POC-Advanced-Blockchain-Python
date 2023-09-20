from common.colors import bcolors
from common.logging import logger, DEFAULT_COLOR


class CommandList:
    def __init__(self):
        self.commands = {}

    def add_command(self, command):
        self.commands[command.type] = command

    def execute(self, command_type, *args, **kwargs):
        command = self.commands.get(command_type)
        if command:
            if command.args:
                if ":" in args[0]:
                    args = args[0].split(":") + list(args[1:])
                else:
                    args = [args[0]] + list(args[1:])
            return command(*args, **kwargs)
        else:
            logger.error(f"Unknown command type: {command_type}")

    def help(self):
        print(f"=== Available commands ===")
        print(f"Type {bcolors.OKCYAN}/<command>{DEFAULT_COLOR} to execute a command")
        for command in self.commands.values():
            print(f"\t{bcolors.OKCYAN}{command.type}{bcolors.ENDC}: {command.description}")
        print(f"==========================")