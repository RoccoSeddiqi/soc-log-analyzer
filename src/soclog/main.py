import sys
from soclog.controller.cli_controller import CLIController

def main() -> int:
    controller = CLIController()
    return controller.run(sys.argv[1:])

if __name__ == "__main__":
    raise SystemExit(main())