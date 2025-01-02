import argparse
from chaincraft import ChaincraftNode

def main():
    parser = argparse.ArgumentParser(description='Chaincraft CLI')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debugging')
    parser.add_argument('-p', '--port', type=int, default=21000, help='Specify port number (default: 21000)')
    parser.add_argument('-r', '--random-port', action='store_true', help='Use a random port number') 
    parser.add_argument('-m', '--memory', action='store_true', help='Use non-persistent memory storage')
    args = parser.parse_args()

    port = args.port if not args.random_port else None
    node = ChaincraftNode(debug=args.debug, persistent=not args.memory, port=port)
    node.start()

    print(f"Node started on port {node.port}")
    print("Enter a message to broadcast (press Ctrl+C to quit):")
    print("Usage: python chaincraft-cli.py [-d] [-p PORT] [-r] [-m]")

    try:
        while True:
            message = input()
            node.create_shared_message(message)
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        node.close()

if __name__ == '__main__':
    main()